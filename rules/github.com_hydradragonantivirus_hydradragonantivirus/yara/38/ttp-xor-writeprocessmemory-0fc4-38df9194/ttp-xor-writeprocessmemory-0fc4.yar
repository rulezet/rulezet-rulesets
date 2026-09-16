rule TTP_XOR_WriteProcessMemory_0fc4 {
  strings:
    $key_0fc4 = { 58 b6 [2] 6a 94 [2] 6c a1 [2] 42 a1 [2] 7d bd }

  condition:
    any of them
}