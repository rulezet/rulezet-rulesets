rule TTP_XOR_QUAD_CurrentVersionRun_5fa7 {
  strings:
    $key_5fa7 = { 0c c8 [2] 28 c6 [2] 03 ea [2] 2d c8 [2] 39 d3 [2] 36 c9 [2] 28 d4 [2] 2a d5 [2] 31 d3 [2] 2d d4 [2] 31 fb }

  condition:
    any of them
}