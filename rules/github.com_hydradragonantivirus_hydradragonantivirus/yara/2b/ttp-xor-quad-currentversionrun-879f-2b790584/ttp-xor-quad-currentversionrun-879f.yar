rule TTP_XOR_QUAD_CurrentVersionRun_879f {
  strings:
    $key_879f = { d4 f0 [2] f0 fe [2] db d2 [2] f5 f0 [2] e1 eb [2] ee f1 [2] f0 ec [2] f2 ed [2] e9 eb [2] f5 ec [2] e9 c3 }

  condition:
    any of them
}