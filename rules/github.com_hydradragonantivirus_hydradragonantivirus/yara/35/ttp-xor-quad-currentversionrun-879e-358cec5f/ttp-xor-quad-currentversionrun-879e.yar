rule TTP_XOR_QUAD_CurrentVersionRun_879e {
  strings:
    $key_879e = { d4 f1 [2] f0 ff [2] db d3 [2] f5 f1 [2] e1 ea [2] ee f0 [2] f0 ed [2] f2 ec [2] e9 ea [2] f5 ed [2] e9 c2 }

  condition:
    any of them
}