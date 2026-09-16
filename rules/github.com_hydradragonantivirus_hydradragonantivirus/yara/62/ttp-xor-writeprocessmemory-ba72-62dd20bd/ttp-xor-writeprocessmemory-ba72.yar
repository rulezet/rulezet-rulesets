rule TTP_XOR_WriteProcessMemory_ba72 {
  strings:
    $key_ba72 = { ed 00 [2] df 22 [2] d9 17 [2] f7 17 [2] c8 0b }

  condition:
    any of them
}