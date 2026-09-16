rule TTP_XOR_QUAD_CurrentVersionRun_3680 {
  strings:
    $key_3680 = { 65 ef [2] 41 e1 [2] 6a cd [2] 44 ef [2] 50 f4 [2] 5f ee [2] 41 f3 [2] 43 f2 [2] 58 f4 [2] 44 f3 [2] 58 dc }

  condition:
    any of them
}