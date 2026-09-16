rule TTP_XOR_QUAD_CurrentVersionRun_8c94 {
  strings:
    $key_8c94 = { df fb [2] fb f5 [2] d0 d9 [2] fe fb [2] ea e0 [2] e5 fa [2] fb e7 [2] f9 e6 [2] e2 e0 [2] fe e7 [2] e2 c8 }

  condition:
    any of them
}