rule TTP_XOR_QUAD_CurrentVersionRun_8c89 {
  strings:
    $key_8c89 = { df e6 [2] fb e8 [2] d0 c4 [2] fe e6 [2] ea fd [2] e5 e7 [2] fb fa [2] f9 fb [2] e2 fd [2] fe fa [2] e2 d5 }

  condition:
    any of them
}