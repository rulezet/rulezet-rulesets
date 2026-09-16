rule TTP_XOR_QUAD_CurrentVersionRun_6fa7 {
  strings:
    $key_6fa7 = { 3c c8 [2] 18 c6 [2] 33 ea [2] 1d c8 [2] 09 d3 [2] 06 c9 [2] 18 d4 [2] 1a d5 [2] 01 d3 [2] 1d d4 [2] 01 fb }

  condition:
    any of them
}