rule TTP_XOR_QUAD_CurrentVersionRun_ae86 {
  strings:
    $key_ae86 = { fd e9 [2] d9 e7 [2] f2 cb [2] dc e9 [2] c8 f2 [2] c7 e8 [2] d9 f5 [2] db f4 [2] c0 f2 [2] dc f5 [2] c0 da }

  condition:
    any of them
}