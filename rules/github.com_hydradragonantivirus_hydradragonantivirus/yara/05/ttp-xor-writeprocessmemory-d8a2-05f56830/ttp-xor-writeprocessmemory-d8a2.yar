rule TTP_XOR_WriteProcessMemory_d8a2 {
  strings:
    $key_d8a2 = { 8f d0 [2] bd f2 [2] bb c7 [2] 95 c7 [2] aa db }

  condition:
    any of them
}