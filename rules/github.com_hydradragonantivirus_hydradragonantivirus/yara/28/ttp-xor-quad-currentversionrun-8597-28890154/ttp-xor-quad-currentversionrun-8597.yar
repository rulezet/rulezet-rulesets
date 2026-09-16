rule TTP_XOR_QUAD_CurrentVersionRun_8597 {
  strings:
    $key_8597 = { d6 f8 [2] f2 f6 [2] d9 da [2] f7 f8 [2] e3 e3 [2] ec f9 [2] f2 e4 [2] f0 e5 [2] eb e3 [2] f7 e4 [2] eb cb }

  condition:
    any of them
}