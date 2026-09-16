rule TTP_XOR_WriteProcessMemory_5316 {
  strings:
    $key_5316 = { 04 64 [2] 36 46 [2] 30 73 [2] 1e 73 [2] 21 6f }

  condition:
    any of them
}