rule TTP_XOR_QUAD_CurrentVersionRun_84bb {
  strings:
    $key_84bb = { d7 d4 [2] f3 da [2] d8 f6 [2] f6 d4 [2] e2 cf [2] ed d5 [2] f3 c8 [2] f1 c9 [2] ea cf [2] f6 c8 [2] ea e7 }

  condition:
    any of them
}