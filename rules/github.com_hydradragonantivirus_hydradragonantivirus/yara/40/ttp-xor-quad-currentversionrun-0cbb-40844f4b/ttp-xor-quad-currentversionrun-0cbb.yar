rule TTP_XOR_QUAD_CurrentVersionRun_0cbb {
  strings:
    $key_0cbb = { 5f d4 [2] 7b da [2] 50 f6 [2] 7e d4 [2] 6a cf [2] 65 d5 [2] 7b c8 [2] 79 c9 [2] 62 cf [2] 7e c8 [2] 62 e7 }

  condition:
    any of them
}