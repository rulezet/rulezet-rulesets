rule TTP_XOR_QUAD_CurrentVersionRun_c0d3 {
  strings:
    $key_c0d3 = { 93 bc [2] b7 b2 [2] 9c 9e [2] b2 bc [2] a6 a7 [2] a9 bd [2] b7 a0 [2] b5 a1 [2] ae a7 [2] b2 a0 [2] ae 8f }

  condition:
    any of them
}