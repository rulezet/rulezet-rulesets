rule TTP_XOR_WriteProcessMemory_b0c1 {
  strings:
    $key_b0c1 = { e7 b3 [2] d5 91 [2] d3 a4 [2] fd a4 [2] c2 b8 }

  condition:
    any of them
}