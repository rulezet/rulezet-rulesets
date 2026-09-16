rule TTP_XOR_QUAD_CurrentVersionRun_d1d3 {
  strings:
    $key_d1d3 = { 82 bc [2] a6 b2 [2] 8d 9e [2] a3 bc [2] b7 a7 [2] b8 bd [2] a6 a0 [2] a4 a1 [2] bf a7 [2] a3 a0 [2] bf 8f }

  condition:
    any of them
}