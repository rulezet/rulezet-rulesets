rule TTP_XOR_WriteProcessMemory_b6ad {
  strings:
    $key_b6ad = { e1 df [2] d3 fd [2] d5 c8 [2] fb c8 [2] c4 d4 }

  condition:
    any of them
}