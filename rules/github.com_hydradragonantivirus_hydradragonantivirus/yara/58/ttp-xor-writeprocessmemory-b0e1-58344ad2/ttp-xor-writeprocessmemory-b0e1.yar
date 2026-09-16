rule TTP_XOR_WriteProcessMemory_b0e1 {
  strings:
    $key_b0e1 = { e7 93 [2] d5 b1 [2] d3 84 [2] fd 84 [2] c2 98 }

  condition:
    any of them
}