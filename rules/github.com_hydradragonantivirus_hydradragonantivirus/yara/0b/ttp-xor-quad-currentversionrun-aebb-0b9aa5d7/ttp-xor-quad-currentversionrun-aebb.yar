rule TTP_XOR_QUAD_CurrentVersionRun_aebb {
  strings:
    $key_aebb = { fd d4 [2] d9 da [2] f2 f6 [2] dc d4 [2] c8 cf [2] c7 d5 [2] d9 c8 [2] db c9 [2] c0 cf [2] dc c8 [2] c0 e7 }

  condition:
    any of them
}