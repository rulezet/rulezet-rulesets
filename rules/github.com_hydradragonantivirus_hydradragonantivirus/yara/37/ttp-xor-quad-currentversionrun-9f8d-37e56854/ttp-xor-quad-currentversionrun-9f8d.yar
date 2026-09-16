rule TTP_XOR_QUAD_CurrentVersionRun_9f8d {
  strings:
    $key_9f8d = { cc e2 [2] e8 ec [2] c3 c0 [2] ed e2 [2] f9 f9 [2] f6 e3 [2] e8 fe [2] ea ff [2] f1 f9 [2] ed fe [2] f1 d1 }

  condition:
    any of them
}