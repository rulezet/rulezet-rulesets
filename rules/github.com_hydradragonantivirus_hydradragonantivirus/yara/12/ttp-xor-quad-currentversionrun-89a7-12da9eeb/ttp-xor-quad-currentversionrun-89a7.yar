rule TTP_XOR_QUAD_CurrentVersionRun_89a7 {
  strings:
    $key_89a7 = { da c8 [2] fe c6 [2] d5 ea [2] fb c8 [2] ef d3 [2] e0 c9 [2] fe d4 [2] fc d5 [2] e7 d3 [2] fb d4 [2] e7 fb }

  condition:
    any of them
}