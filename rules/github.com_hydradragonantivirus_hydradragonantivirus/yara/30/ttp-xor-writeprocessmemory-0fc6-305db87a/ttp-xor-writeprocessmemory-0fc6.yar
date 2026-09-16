rule TTP_XOR_WriteProcessMemory_0fc6 {
  strings:
    $key_0fc6 = { 58 b4 [2] 6a 96 [2] 6c a3 [2] 42 a3 [2] 7d bf }

  condition:
    any of them
}