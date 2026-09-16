rule TTP_XOR_WriteProcessMemory_ba38 {
  strings:
    $key_ba38 = { ed 4a [2] df 68 [2] d9 5d [2] f7 5d [2] c8 41 }

  condition:
    any of them
}