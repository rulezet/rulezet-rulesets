rule TTP_XOR_QUAD_CurrentVersionRun_9a83 {
  strings:
    $key_9a83 = { c9 ec [2] ed e2 [2] c6 ce [2] e8 ec [2] fc f7 [2] f3 ed [2] ed f0 [2] ef f1 [2] f4 f7 [2] e8 f0 [2] f4 df }

  condition:
    any of them
}