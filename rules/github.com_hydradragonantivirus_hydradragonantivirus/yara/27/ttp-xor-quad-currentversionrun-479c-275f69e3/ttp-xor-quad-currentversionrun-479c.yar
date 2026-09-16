rule TTP_XOR_QUAD_CurrentVersionRun_479c {
  strings:
    $key_479c = { 14 f3 [2] 30 fd [2] 1b d1 [2] 35 f3 [2] 21 e8 [2] 2e f2 [2] 30 ef [2] 32 ee [2] 29 e8 [2] 35 ef [2] 29 c0 }

  condition:
    any of them
}