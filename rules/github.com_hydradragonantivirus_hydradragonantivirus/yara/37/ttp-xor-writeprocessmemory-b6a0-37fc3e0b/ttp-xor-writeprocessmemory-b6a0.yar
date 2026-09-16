rule TTP_XOR_WriteProcessMemory_b6a0 {
  strings:
    $key_b6a0 = { e1 d2 [2] d3 f0 [2] d5 c5 [2] fb c5 [2] c4 d9 }

  condition:
    any of them
}