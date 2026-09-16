rule TTP_XOR_WriteProcessMemory_b6a5 {
  strings:
    $key_b6a5 = { e1 d7 [2] d3 f5 [2] d5 c0 [2] fb c0 [2] c4 dc }

  condition:
    any of them
}