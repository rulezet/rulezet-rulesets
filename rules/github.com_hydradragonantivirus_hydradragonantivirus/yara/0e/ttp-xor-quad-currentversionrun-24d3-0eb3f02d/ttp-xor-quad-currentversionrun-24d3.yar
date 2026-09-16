rule TTP_XOR_QUAD_CurrentVersionRun_24d3 {
  strings:
    $key_24d3 = { 77 bc [2] 53 b2 [2] 78 9e [2] 56 bc [2] 42 a7 [2] 4d bd [2] 53 a0 [2] 51 a1 [2] 4a a7 [2] 56 a0 [2] 4a 8f }

  condition:
    any of them
}