rule TTP_XOR_QUAD_CurrentVersionRun_9985 {
  strings:
    $key_9985 = { ca ea [2] ee e4 [2] c5 c8 [2] eb ea [2] ff f1 [2] f0 eb [2] ee f6 [2] ec f7 [2] f7 f1 [2] eb f6 [2] f7 d9 }

  condition:
    any of them
}