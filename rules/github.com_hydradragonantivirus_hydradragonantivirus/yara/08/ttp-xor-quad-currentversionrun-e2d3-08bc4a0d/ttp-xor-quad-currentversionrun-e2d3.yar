rule TTP_XOR_QUAD_CurrentVersionRun_e2d3 {
  strings:
    $key_e2d3 = { b1 bc [2] 95 b2 [2] be 9e [2] 90 bc [2] 84 a7 [2] 8b bd [2] 95 a0 [2] 97 a1 [2] 8c a7 [2] 90 a0 [2] 8c 8f }

  condition:
    any of them
}