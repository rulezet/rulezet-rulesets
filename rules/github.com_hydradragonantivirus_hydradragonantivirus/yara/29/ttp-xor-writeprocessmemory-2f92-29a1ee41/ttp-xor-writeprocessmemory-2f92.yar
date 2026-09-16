rule TTP_XOR_WriteProcessMemory_2f92 {
  strings:
    $key_2f92 = { 78 e0 [2] 4a c2 [2] 4c f7 [2] 62 f7 [2] 5d eb }

  condition:
    any of them
}