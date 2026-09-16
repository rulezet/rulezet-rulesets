rule TTP_XOR_WriteProcessMemory_b0b0 {
  strings:
    $key_b0b0 = { e7 c2 [2] d5 e0 [2] d3 d5 [2] fd d5 [2] c2 c9 }

  condition:
    any of them
}