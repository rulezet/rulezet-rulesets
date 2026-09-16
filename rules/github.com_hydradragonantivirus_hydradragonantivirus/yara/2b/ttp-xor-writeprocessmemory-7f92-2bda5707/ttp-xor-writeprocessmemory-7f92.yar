rule TTP_XOR_WriteProcessMemory_7f92 {
  strings:
    $key_7f92 = { 28 e0 [2] 1a c2 [2] 1c f7 [2] 32 f7 [2] 0d eb }

  condition:
    any of them
}