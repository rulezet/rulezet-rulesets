rule TTP_XOR_QUAD_CurrentVersionRun_7cbb {
  strings:
    $key_7cbb = { 2f d4 [2] 0b da [2] 20 f6 [2] 0e d4 [2] 1a cf [2] 15 d5 [2] 0b c8 [2] 09 c9 [2] 12 cf [2] 0e c8 [2] 12 e7 }

  condition:
    any of them
}