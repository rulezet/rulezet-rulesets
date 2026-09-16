rule TTP_XOR_QUAD_CurrentVersionRun_aba9 {
  strings:
    $key_aba9 = { f8 c6 [2] dc c8 [2] f7 e4 [2] d9 c6 [2] cd dd [2] c2 c7 [2] dc da [2] de db [2] c5 dd [2] d9 da [2] c5 f5 }

  condition:
    any of them
}