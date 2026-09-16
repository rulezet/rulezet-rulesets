rule TTP_XOR_QUAD_CurrentVersionRun_879a {
  strings:
    $key_879a = { d4 f5 [2] f0 fb [2] db d7 [2] f5 f5 [2] e1 ee [2] ee f4 [2] f0 e9 [2] f2 e8 [2] e9 ee [2] f5 e9 [2] e9 c6 }

  condition:
    any of them
}