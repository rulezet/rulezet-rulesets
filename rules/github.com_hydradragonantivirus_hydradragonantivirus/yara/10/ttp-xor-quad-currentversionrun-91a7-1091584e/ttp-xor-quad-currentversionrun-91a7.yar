rule TTP_XOR_QUAD_CurrentVersionRun_91a7 {
  strings:
    $key_91a7 = { c2 c8 [2] e6 c6 [2] cd ea [2] e3 c8 [2] f7 d3 [2] f8 c9 [2] e6 d4 [2] e4 d5 [2] ff d3 [2] e3 d4 [2] ff fb }

  condition:
    any of them
}