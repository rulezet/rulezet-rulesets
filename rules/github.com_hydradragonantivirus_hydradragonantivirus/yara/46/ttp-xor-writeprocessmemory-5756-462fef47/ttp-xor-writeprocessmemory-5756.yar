rule TTP_XOR_WriteProcessMemory_5756 {
  strings:
    $key_5756 = { 00 24 [2] 32 06 [2] 34 33 [2] 1a 33 [2] 25 2f }

  condition:
    any of them
}