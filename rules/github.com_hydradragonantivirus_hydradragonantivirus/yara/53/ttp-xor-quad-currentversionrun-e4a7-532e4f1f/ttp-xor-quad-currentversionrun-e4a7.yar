rule TTP_XOR_QUAD_CurrentVersionRun_e4a7 {
  strings:
    $key_e4a7 = { b7 c8 [2] 93 c6 [2] b8 ea [2] 96 c8 [2] 82 d3 [2] 8d c9 [2] 93 d4 [2] 91 d5 [2] 8a d3 [2] 96 d4 [2] 8a fb }

  condition:
    any of them
}