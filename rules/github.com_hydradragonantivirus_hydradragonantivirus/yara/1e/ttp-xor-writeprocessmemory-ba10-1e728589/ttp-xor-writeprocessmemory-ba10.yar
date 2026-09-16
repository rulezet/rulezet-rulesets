rule TTP_XOR_WriteProcessMemory_ba10 {
  strings:
    $key_ba10 = { ed 62 [2] df 40 [2] d9 75 [2] f7 75 [2] c8 69 }

  condition:
    any of them
}