rule TTP_XOR_QUAD_CurrentVersionRun_9b83 {
  strings:
    $key_9b83 = { c8 ec [2] ec e2 [2] c7 ce [2] e9 ec [2] fd f7 [2] f2 ed [2] ec f0 [2] ee f1 [2] f5 f7 [2] e9 f0 [2] f5 df }

  condition:
    any of them
}