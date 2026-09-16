rule TTP_XOR_QUAD_CurrentVersionRun_e1a7 {
  strings:
    $key_e1a7 = { b2 c8 [2] 96 c6 [2] bd ea [2] 93 c8 [2] 87 d3 [2] 88 c9 [2] 96 d4 [2] 94 d5 [2] 8f d3 [2] 93 d4 [2] 8f fb }

  condition:
    any of them
}