rule TTP_XOR_QUAD_CurrentVersionRun_fcd7 {
  strings:
    $key_fcd7 = { af b8 [2] 8b b6 [2] a0 9a [2] 8e b8 [2] 9a a3 [2] 95 b9 [2] 8b a4 [2] 89 a5 [2] 92 a3 [2] 8e a4 [2] 92 8b }

  condition:
    any of them
}