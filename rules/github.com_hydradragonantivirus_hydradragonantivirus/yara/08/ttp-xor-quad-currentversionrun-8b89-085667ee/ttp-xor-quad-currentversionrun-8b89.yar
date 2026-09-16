rule TTP_XOR_QUAD_CurrentVersionRun_8b89 {
  strings:
    $key_8b89 = { d8 e6 [2] fc e8 [2] d7 c4 [2] f9 e6 [2] ed fd [2] e2 e7 [2] fc fa [2] fe fb [2] e5 fd [2] f9 fa [2] e5 d5 }

  condition:
    any of them
}