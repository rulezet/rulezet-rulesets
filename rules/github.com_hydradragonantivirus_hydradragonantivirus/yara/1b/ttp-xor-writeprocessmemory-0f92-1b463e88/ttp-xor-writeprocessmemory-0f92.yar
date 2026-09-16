rule TTP_XOR_WriteProcessMemory_0f92 {
  strings:
    $key_0f92 = { 58 e0 [2] 6a c2 [2] 6c f7 [2] 42 f7 [2] 7d eb }

  condition:
    any of them
}