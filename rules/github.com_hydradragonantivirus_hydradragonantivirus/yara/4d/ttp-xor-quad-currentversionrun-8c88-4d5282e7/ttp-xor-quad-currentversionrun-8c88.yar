rule TTP_XOR_QUAD_CurrentVersionRun_8c88 {
  strings:
    $key_8c88 = { df e7 [2] fb e9 [2] d0 c5 [2] fe e7 [2] ea fc [2] e5 e6 [2] fb fb [2] f9 fa [2] e2 fc [2] fe fb [2] e2 d4 }

  condition:
    any of them
}