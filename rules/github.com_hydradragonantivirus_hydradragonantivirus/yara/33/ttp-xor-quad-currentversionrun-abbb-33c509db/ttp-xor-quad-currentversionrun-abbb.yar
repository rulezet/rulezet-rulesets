rule TTP_XOR_QUAD_CurrentVersionRun_abbb {
  strings:
    $key_abbb = { f8 d4 [2] dc da [2] f7 f6 [2] d9 d4 [2] cd cf [2] c2 d5 [2] dc c8 [2] de c9 [2] c5 cf [2] d9 c8 [2] c5 e7 }

  condition:
    any of them
}