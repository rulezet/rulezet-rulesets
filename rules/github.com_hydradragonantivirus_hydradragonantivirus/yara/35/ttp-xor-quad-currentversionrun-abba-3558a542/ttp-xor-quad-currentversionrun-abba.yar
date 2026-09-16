rule TTP_XOR_QUAD_CurrentVersionRun_abba {
  strings:
    $key_abba = { f8 d5 [2] dc db [2] f7 f7 [2] d9 d5 [2] cd ce [2] c2 d4 [2] dc c9 [2] de c8 [2] c5 ce [2] d9 c9 [2] c5 e6 }

  condition:
    any of them
}