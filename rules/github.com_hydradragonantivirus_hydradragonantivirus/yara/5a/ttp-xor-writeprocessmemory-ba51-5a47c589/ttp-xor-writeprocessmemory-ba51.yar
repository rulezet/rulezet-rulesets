rule TTP_XOR_WriteProcessMemory_ba51 {
  strings:
    $key_ba51 = { ed 23 [2] df 01 [2] d9 34 [2] f7 34 [2] c8 28 }

  condition:
    any of them
}