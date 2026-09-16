rule TTP_XOR_WriteProcessMemory_0fc2 {
  strings:
    $key_0fc2 = { 58 b0 [2] 6a 92 [2] 6c a7 [2] 42 a7 [2] 7d bb }

  condition:
    any of them
}