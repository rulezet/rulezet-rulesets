rule TTP_XOR_QUAD_CurrentVersionRun_8798 {
  strings:
    $key_8798 = { d4 f7 [2] f0 f9 [2] db d5 [2] f5 f7 [2] e1 ec [2] ee f6 [2] f0 eb [2] f2 ea [2] e9 ec [2] f5 eb [2] e9 c4 }

  condition:
    any of them
}