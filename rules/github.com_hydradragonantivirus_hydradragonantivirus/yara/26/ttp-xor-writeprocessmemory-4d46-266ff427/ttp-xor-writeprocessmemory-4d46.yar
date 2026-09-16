rule TTP_XOR_WriteProcessMemory_4d46 {
  strings:
    $key_4d46 = { 1a 34 [2] 28 16 [2] 2e 23 [2] 00 23 [2] 3f 3f }

  condition:
    any of them
}