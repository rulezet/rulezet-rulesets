rule TTP_XOR_WriteProcessMemory_b6a4 {
  strings:
    $key_b6a4 = { e1 d6 [2] d3 f4 [2] d5 c1 [2] fb c1 [2] c4 dd }

  condition:
    any of them
}