rule TTP_XOR_QUAD_CurrentVersionRun_9f97 {
  strings:
    $key_9f97 = { cc f8 [2] e8 f6 [2] c3 da [2] ed f8 [2] f9 e3 [2] f6 f9 [2] e8 e4 [2] ea e5 [2] f1 e3 [2] ed e4 [2] f1 cb }

  condition:
    any of them
}