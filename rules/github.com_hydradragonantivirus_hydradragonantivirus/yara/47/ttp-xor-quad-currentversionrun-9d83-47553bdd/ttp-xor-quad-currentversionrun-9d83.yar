rule TTP_XOR_QUAD_CurrentVersionRun_9d83 {
  strings:
    $key_9d83 = { ce ec [2] ea e2 [2] c1 ce [2] ef ec [2] fb f7 [2] f4 ed [2] ea f0 [2] e8 f1 [2] f3 f7 [2] ef f0 [2] f3 df }

  condition:
    any of them
}