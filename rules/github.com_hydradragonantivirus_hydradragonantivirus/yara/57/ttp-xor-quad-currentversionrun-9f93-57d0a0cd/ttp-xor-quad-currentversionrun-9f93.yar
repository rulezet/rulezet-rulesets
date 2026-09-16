rule TTP_XOR_QUAD_CurrentVersionRun_9f93 {
  strings:
    $key_9f93 = { cc fc [2] e8 f2 [2] c3 de [2] ed fc [2] f9 e7 [2] f6 fd [2] e8 e0 [2] ea e1 [2] f1 e7 [2] ed e0 [2] f1 cf }

  condition:
    any of them
}