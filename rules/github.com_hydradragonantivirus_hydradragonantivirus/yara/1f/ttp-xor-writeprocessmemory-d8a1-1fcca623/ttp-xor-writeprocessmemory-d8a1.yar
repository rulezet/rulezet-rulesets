rule TTP_XOR_WriteProcessMemory_d8a1 {
  strings:
    $key_d8a1 = { 8f d3 [2] bd f1 [2] bb c4 [2] 95 c4 [2] aa d8 }

  condition:
    any of them
}