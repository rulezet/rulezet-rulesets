rule TTP_XOR_QUAD_CurrentVersionRun_aec9 {
  strings:
    $key_aec9 = { fd a6 [2] d9 a8 [2] f2 84 [2] dc a6 [2] c8 bd [2] c7 a7 [2] d9 ba [2] db bb [2] c0 bd [2] dc ba [2] c0 95 }

  condition:
    any of them
}