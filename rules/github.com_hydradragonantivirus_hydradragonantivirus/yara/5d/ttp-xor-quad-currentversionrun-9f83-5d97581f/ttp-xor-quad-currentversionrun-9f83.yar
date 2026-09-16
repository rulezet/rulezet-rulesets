rule TTP_XOR_QUAD_CurrentVersionRun_9f83 {
  strings:
    $key_9f83 = { cc ec [2] e8 e2 [2] c3 ce [2] ed ec [2] f9 f7 [2] f6 ed [2] e8 f0 [2] ea f1 [2] f1 f7 [2] ed f0 [2] f1 df }

  condition:
    any of them
}