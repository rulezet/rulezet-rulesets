rule TTP_XOR_QUAD_CurrentVersionRun_9c8b {
  strings:
    $key_9c8b = { cf e4 [2] eb ea [2] c0 c6 [2] ee e4 [2] fa ff [2] f5 e5 [2] eb f8 [2] e9 f9 [2] f2 ff [2] ee f8 [2] f2 d7 }

  condition:
    any of them
}