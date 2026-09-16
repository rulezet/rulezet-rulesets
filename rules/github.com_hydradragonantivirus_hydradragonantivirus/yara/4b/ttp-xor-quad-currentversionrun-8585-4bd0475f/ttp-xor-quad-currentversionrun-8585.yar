rule TTP_XOR_QUAD_CurrentVersionRun_8585 {
  strings:
    $key_8585 = { d6 ea [2] f2 e4 [2] d9 c8 [2] f7 ea [2] e3 f1 [2] ec eb [2] f2 f6 [2] f0 f7 [2] eb f1 [2] f7 f6 [2] eb d9 }

  condition:
    any of them
}