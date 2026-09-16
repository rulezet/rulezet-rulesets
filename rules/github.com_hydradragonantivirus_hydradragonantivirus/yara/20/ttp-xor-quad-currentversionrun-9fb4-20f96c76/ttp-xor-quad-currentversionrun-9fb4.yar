rule TTP_XOR_QUAD_CurrentVersionRun_9fb4 {
  strings:
    $key_9fb4 = { cc db [2] e8 d5 [2] c3 f9 [2] ed db [2] f9 c0 [2] f6 da [2] e8 c7 [2] ea c6 [2] f1 c0 [2] ed c7 [2] f1 e8 }

  condition:
    any of them
}