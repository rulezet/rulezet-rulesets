rule TTP_XOR_WriteProcessMemory_b0c0 {
  strings:
    $key_b0c0 = { e7 b2 [2] d5 90 [2] d3 a5 [2] fd a5 [2] c2 b9 }

  condition:
    any of them
}