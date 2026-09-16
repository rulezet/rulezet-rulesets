rule TTP_XOR_QUAD_CurrentVersionRun_aeb4 {
  strings:
    $key_aeb4 = { fd db [2] d9 d5 [2] f2 f9 [2] dc db [2] c8 c0 [2] c7 da [2] d9 c7 [2] db c6 [2] c0 c0 [2] dc c7 [2] c0 e8 }

  condition:
    any of them
}