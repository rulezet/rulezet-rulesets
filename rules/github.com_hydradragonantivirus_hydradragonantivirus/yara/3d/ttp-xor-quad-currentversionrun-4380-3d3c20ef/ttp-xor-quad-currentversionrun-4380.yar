rule TTP_XOR_QUAD_CurrentVersionRun_4380 {
  strings:
    $key_4380 = { 10 ef [2] 34 e1 [2] 1f cd [2] 31 ef [2] 25 f4 [2] 2a ee [2] 34 f3 [2] 36 f2 [2] 2d f4 [2] 31 f3 [2] 2d dc }

  condition:
    any of them
}