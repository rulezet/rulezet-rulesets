rule TTP_XOR_QUAD_CurrentVersionRun_3cbb {
  strings:
    $key_3cbb = { 6f d4 [2] 4b da [2] 60 f6 [2] 4e d4 [2] 5a cf [2] 55 d5 [2] 4b c8 [2] 49 c9 [2] 52 cf [2] 4e c8 [2] 52 e7 }

  condition:
    any of them
}