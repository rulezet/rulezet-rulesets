rule TTP_XOR_QUAD_CurrentVersionRun_fcd6 {
  strings:
    $key_fcd6 = { af b9 [2] 8b b7 [2] a0 9b [2] 8e b9 [2] 9a a2 [2] 95 b8 [2] 8b a5 [2] 89 a4 [2] 92 a2 [2] 8e a5 [2] 92 8a }

  condition:
    any of them
}