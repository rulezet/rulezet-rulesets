rule TTP_XOR_WriteProcessMemory_d8a5 {
  strings:
    $key_d8a5 = { 8f d7 [2] bd f5 [2] bb c0 [2] 95 c0 [2] aa dc }

  condition:
    any of them
}