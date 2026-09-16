rule TTP_XOR_QUAD_CurrentVersionRun_5680 {
  strings:
    $key_5680 = { 05 ef [2] 21 e1 [2] 0a cd [2] 24 ef [2] 30 f4 [2] 3f ee [2] 21 f3 [2] 23 f2 [2] 38 f4 [2] 24 f3 [2] 38 dc }

  condition:
    any of them
}