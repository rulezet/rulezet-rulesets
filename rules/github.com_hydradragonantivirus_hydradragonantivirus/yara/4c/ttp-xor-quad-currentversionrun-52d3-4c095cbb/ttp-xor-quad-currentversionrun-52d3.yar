rule TTP_XOR_QUAD_CurrentVersionRun_52d3 {
  strings:
    $key_52d3 = { 01 bc [2] 25 b2 [2] 0e 9e [2] 20 bc [2] 34 a7 [2] 3b bd [2] 25 a0 [2] 27 a1 [2] 3c a7 [2] 20 a0 [2] 3c 8f }

  condition:
    any of them
}