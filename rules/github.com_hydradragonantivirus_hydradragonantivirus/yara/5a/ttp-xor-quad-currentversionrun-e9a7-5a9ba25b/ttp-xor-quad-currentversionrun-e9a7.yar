rule TTP_XOR_QUAD_CurrentVersionRun_e9a7 {
  strings:
    $key_e9a7 = { ba c8 [2] 9e c6 [2] b5 ea [2] 9b c8 [2] 8f d3 [2] 80 c9 [2] 9e d4 [2] 9c d5 [2] 87 d3 [2] 9b d4 [2] 87 fb }

  condition:
    any of them
}