rule TTP_XOR_QUAD_CurrentVersionRun_8b94 {
  strings:
    $key_8b94 = { d8 fb [2] fc f5 [2] d7 d9 [2] f9 fb [2] ed e0 [2] e2 fa [2] fc e7 [2] fe e6 [2] e5 e0 [2] f9 e7 [2] e5 c8 }

  condition:
    any of them
}