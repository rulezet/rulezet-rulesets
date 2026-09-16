rule TTP_XOR_QUAD_CurrentVersionRun_879d {
  strings:
    $key_879d = { d4 f2 [2] f0 fc [2] db d0 [2] f5 f2 [2] e1 e9 [2] ee f3 [2] f0 ee [2] f2 ef [2] e9 e9 [2] f5 ee [2] e9 c1 }

  condition:
    any of them
}