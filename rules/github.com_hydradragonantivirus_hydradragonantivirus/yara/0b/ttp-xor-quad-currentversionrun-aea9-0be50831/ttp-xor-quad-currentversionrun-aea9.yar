rule TTP_XOR_QUAD_CurrentVersionRun_aea9 {
  strings:
    $key_aea9 = { fd c6 [2] d9 c8 [2] f2 e4 [2] dc c6 [2] c8 dd [2] c7 c7 [2] d9 da [2] db db [2] c0 dd [2] dc da [2] c0 f5 }

  condition:
    any of them
}