rule TTP_XOR_WriteProcessMemory_ba13 {
  strings:
    $key_ba13 = { ed 61 [2] df 43 [2] d9 76 [2] f7 76 [2] c8 6a }

  condition:
    any of them
}