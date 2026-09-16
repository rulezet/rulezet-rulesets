rule TTP_XOR_WriteProcessMemory_4d26 {
  strings:
    $key_4d26 = { 1a 54 [2] 28 76 [2] 2e 43 [2] 00 43 [2] 3f 5f }

  condition:
    any of them
}