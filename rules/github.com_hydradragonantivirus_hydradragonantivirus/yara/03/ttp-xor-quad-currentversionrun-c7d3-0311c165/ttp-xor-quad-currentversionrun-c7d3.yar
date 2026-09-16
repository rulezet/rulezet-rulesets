rule TTP_XOR_QUAD_CurrentVersionRun_c7d3 {
  strings:
    $key_c7d3 = { 94 bc [2] b0 b2 [2] 9b 9e [2] b5 bc [2] a1 a7 [2] ae bd [2] b0 a0 [2] b2 a1 [2] a9 a7 [2] b5 a0 [2] a9 8f }

  condition:
    any of them
}