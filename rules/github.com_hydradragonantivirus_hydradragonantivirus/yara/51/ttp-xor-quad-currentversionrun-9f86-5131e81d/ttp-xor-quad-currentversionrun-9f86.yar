rule TTP_XOR_QUAD_CurrentVersionRun_9f86 {
  strings:
    $key_9f86 = { cc e9 [2] e8 e7 [2] c3 cb [2] ed e9 [2] f9 f2 [2] f6 e8 [2] e8 f5 [2] ea f4 [2] f1 f2 [2] ed f5 [2] f1 da }

  condition:
    any of them
}