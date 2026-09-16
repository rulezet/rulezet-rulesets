rule TTP_XOR_QUAD_CurrentVersionRun_879c {
  strings:
    $key_879c = { d4 f3 [2] f0 fd [2] db d1 [2] f5 f3 [2] e1 e8 [2] ee f2 [2] f0 ef [2] f2 ee [2] e9 e8 [2] f5 ef [2] e9 c0 }

  condition:
    any of them
}