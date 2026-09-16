rule TTP_XOR_QUAD_CurrentVersionRun_9f8b {
  strings:
    $key_9f8b = { cc e4 [2] e8 ea [2] c3 c6 [2] ed e4 [2] f9 ff [2] f6 e5 [2] e8 f8 [2] ea f9 [2] f1 ff [2] ed f8 [2] f1 d7 }

  condition:
    any of them
}