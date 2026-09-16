rule TTP_XOR_WriteProcessMemory_7316 {
  strings:
    $key_7316 = { 24 64 [2] 16 46 [2] 10 73 [2] 3e 73 [2] 01 6f }

  condition:
    any of them
}