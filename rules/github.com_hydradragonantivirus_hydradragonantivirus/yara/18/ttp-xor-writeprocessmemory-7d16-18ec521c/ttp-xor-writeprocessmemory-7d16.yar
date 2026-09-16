rule TTP_XOR_WriteProcessMemory_7d16 {
  strings:
    $key_7d16 = { 2a 64 [2] 18 46 [2] 1e 73 [2] 30 73 [2] 0f 6f }

  condition:
    any of them
}