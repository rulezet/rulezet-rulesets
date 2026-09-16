rule TTP_XOR_QUAD_CurrentVersionRun_c2d3 {
  strings:
    $key_c2d3 = { 91 bc [2] b5 b2 [2] 9e 9e [2] b0 bc [2] a4 a7 [2] ab bd [2] b5 a0 [2] b7 a1 [2] ac a7 [2] b0 a0 [2] ac 8f }

  condition:
    any of them
}