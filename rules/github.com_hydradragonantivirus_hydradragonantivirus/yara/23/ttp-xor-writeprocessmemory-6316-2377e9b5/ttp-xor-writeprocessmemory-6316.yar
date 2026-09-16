rule TTP_XOR_WriteProcessMemory_6316 {
  strings:
    $key_6316 = { 34 64 [2] 06 46 [2] 00 73 [2] 2e 73 [2] 11 6f }

  condition:
    any of them
}