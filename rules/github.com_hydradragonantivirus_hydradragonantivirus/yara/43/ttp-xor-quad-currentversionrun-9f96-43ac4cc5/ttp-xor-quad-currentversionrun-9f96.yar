rule TTP_XOR_QUAD_CurrentVersionRun_9f96 {
  strings:
    $key_9f96 = { cc f9 [2] e8 f7 [2] c3 db [2] ed f9 [2] f9 e2 [2] f6 f8 [2] e8 e5 [2] ea e4 [2] f1 e2 [2] ed e5 [2] f1 ca }

  condition:
    any of them
}