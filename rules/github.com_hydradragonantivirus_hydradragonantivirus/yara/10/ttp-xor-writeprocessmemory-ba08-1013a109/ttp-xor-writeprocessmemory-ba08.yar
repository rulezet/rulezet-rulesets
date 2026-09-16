rule TTP_XOR_WriteProcessMemory_ba08 {
  strings:
    $key_ba08 = { ed 7a [2] df 58 [2] d9 6d [2] f7 6d [2] c8 71 }

  condition:
    any of them
}