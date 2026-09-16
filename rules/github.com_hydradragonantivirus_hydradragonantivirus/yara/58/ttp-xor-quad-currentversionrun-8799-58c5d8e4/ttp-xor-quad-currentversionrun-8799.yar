rule TTP_XOR_QUAD_CurrentVersionRun_8799 {
  strings:
    $key_8799 = { d4 f6 [2] f0 f8 [2] db d4 [2] f5 f6 [2] e1 ed [2] ee f7 [2] f0 ea [2] f2 eb [2] e9 ed [2] f5 ea [2] e9 c5 }

  condition:
    any of them
}