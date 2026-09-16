rule TTP_XOR_QUAD_CurrentVersionRun_c4d3 {
  strings:
    $key_c4d3 = { 97 bc [2] b3 b2 [2] 98 9e [2] b6 bc [2] a2 a7 [2] ad bd [2] b3 a0 [2] b1 a1 [2] aa a7 [2] b6 a0 [2] aa 8f }

  condition:
    any of them
}