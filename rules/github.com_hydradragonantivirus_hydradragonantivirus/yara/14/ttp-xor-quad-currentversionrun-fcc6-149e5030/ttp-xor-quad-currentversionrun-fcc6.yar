rule TTP_XOR_QUAD_CurrentVersionRun_fcc6 {
  strings:
    $key_fcc6 = { af a9 [2] 8b a7 [2] a0 8b [2] 8e a9 [2] 9a b2 [2] 95 a8 [2] 8b b5 [2] 89 b4 [2] 92 b2 [2] 8e b5 [2] 92 9a }

  condition:
    any of them
}