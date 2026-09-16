rule TTP_XOR_QUAD_CurrentVersionRun_1cbb {
  strings:
    $key_1cbb = { 4f d4 [2] 6b da [2] 40 f6 [2] 6e d4 [2] 7a cf [2] 75 d5 [2] 6b c8 [2] 69 c9 [2] 72 cf [2] 6e c8 [2] 72 e7 }

  condition:
    any of them
}