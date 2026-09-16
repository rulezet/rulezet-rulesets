rule TTP_XOR_WriteProcessMemory_0fc1 {
  strings:
    $key_0fc1 = { 58 b3 [2] 6a 91 [2] 6c a4 [2] 42 a4 [2] 7d b8 }

  condition:
    any of them
}