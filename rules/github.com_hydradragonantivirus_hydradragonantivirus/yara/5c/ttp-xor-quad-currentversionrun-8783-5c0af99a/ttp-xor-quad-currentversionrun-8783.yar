rule TTP_XOR_QUAD_CurrentVersionRun_8783 {
  strings:
    $key_8783 = { d4 ec [2] f0 e2 [2] db ce [2] f5 ec [2] e1 f7 [2] ee ed [2] f0 f0 [2] f2 f1 [2] e9 f7 [2] f5 f0 [2] e9 df }

  condition:
    any of them
}