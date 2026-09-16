rule TTP_XOR_WriteProcessMemory_d8a7 {
  strings:
    $key_d8a7 = { 8f d5 [2] bd f7 [2] bb c2 [2] 95 c2 [2] aa de }

  condition:
    any of them
}