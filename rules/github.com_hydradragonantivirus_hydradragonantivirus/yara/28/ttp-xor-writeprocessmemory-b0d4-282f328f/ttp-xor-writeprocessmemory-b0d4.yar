rule TTP_XOR_WriteProcessMemory_b0d4 {
  strings:
    $key_b0d4 = { e7 a6 [2] d5 84 [2] d3 b1 [2] fd b1 [2] c2 ad }

  condition:
    any of them
}