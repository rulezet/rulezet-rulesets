rule TTP_XOR_WriteProcessMemory_0fc0 {
  strings:
    $key_0fc0 = { 58 b2 [2] 6a 90 [2] 6c a5 [2] 42 a5 [2] 7d b9 }

  condition:
    any of them
}