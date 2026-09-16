rule TTP_XOR_QUAD_CurrentVersionRun_8c9a {
  strings:
    $key_8c9a = { df f5 [2] fb fb [2] d0 d7 [2] fe f5 [2] ea ee [2] e5 f4 [2] fb e9 [2] f9 e8 [2] e2 ee [2] fe e9 [2] e2 c6 }

  condition:
    any of them
}