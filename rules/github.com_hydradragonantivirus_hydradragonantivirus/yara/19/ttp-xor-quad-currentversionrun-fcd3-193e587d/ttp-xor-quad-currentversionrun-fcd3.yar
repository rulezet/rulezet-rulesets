rule TTP_XOR_QUAD_CurrentVersionRun_fcd3 {
  strings:
    $key_fcd3 = { af bc [2] 8b b2 [2] a0 9e [2] 8e bc [2] 9a a7 [2] 95 bd [2] 8b a0 [2] 89 a1 [2] 92 a7 [2] 8e a0 [2] 92 8f }

  condition:
    any of them
}