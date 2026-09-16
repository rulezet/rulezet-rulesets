rule TTP_XOR_QUAD_CurrentVersionRun_3196 {
  strings:
    $key_3196 = { 62 f9 [2] 46 f7 [2] 6d db [2] 43 f9 [2] 57 e2 [2] 58 f8 [2] 46 e5 [2] 44 e4 [2] 5f e2 [2] 43 e5 [2] 5f ca }

  condition:
    any of them
}