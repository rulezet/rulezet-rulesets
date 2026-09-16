rule TTP_XOR_QUAD_CurrentVersionRun_ae82 {
  strings:
    $key_ae82 = { fd ed [2] d9 e3 [2] f2 cf [2] dc ed [2] c8 f6 [2] c7 ec [2] d9 f1 [2] db f0 [2] c0 f6 [2] dc f1 [2] c0 de }

  condition:
    any of them
}