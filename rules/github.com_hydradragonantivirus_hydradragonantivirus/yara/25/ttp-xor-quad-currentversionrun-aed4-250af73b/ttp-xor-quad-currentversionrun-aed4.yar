rule TTP_XOR_QUAD_CurrentVersionRun_aed4 {
  strings:
    $key_aed4 = { fd bb [2] d9 b5 [2] f2 99 [2] dc bb [2] c8 a0 [2] c7 ba [2] d9 a7 [2] db a6 [2] c0 a0 [2] dc a7 [2] c0 88 }

  condition:
    any of them
}