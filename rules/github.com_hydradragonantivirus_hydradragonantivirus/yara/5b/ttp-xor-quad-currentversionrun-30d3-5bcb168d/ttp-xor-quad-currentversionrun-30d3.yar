rule TTP_XOR_QUAD_CurrentVersionRun_30d3 {
  strings:
    $key_30d3 = { 63 bc [2] 47 b2 [2] 6c 9e [2] 42 bc [2] 56 a7 [2] 59 bd [2] 47 a0 [2] 45 a1 [2] 5e a7 [2] 42 a0 [2] 5e 8f }

  condition:
    any of them
}