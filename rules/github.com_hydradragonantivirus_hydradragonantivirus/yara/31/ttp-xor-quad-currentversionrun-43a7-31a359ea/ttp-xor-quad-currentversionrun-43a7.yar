rule TTP_XOR_QUAD_CurrentVersionRun_43a7 {
  strings:
    $key_43a7 = { 10 c8 [2] 34 c6 [2] 1f ea [2] 31 c8 [2] 25 d3 [2] 2a c9 [2] 34 d4 [2] 36 d5 [2] 2d d3 [2] 31 d4 [2] 2d fb }

  condition:
    any of them
}