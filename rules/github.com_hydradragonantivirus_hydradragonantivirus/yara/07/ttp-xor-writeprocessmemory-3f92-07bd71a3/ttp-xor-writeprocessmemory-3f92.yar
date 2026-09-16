rule TTP_XOR_WriteProcessMemory_3f92 {
  strings:
    $key_3f92 = { 68 e0 [2] 5a c2 [2] 5c f7 [2] 72 f7 [2] 4d eb }

  condition:
    any of them
}