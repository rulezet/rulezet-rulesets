rule TTP_XOR_WriteProcessMemory_ba26 {
  strings:
    $key_ba26 = { ed 54 [2] df 76 [2] d9 43 [2] f7 43 [2] c8 5f }

  condition:
    any of them
}