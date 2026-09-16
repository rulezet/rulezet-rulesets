rule TTP_XOR_QUAD_CurrentVersionRun_33a7 {
  strings:
    $key_33a7 = { 60 c8 [2] 44 c6 [2] 6f ea [2] 41 c8 [2] 55 d3 [2] 5a c9 [2] 44 d4 [2] 46 d5 [2] 5d d3 [2] 41 d4 [2] 5d fb }

  condition:
    any of them
}