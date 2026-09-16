rule TTP_XOR_WriteProcessMemory_0fc5 {
  strings:
    $key_0fc5 = { 58 b7 [2] 6a 95 [2] 6c a0 [2] 42 a0 [2] 7d bc }

  condition:
    any of them
}