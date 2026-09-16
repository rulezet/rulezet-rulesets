rule TTP_XOR_QUAD_CurrentVersionRun_8e89 {
  strings:
    $key_8e89 = { dd e6 [2] f9 e8 [2] d2 c4 [2] fc e6 [2] e8 fd [2] e7 e7 [2] f9 fa [2] fb fb [2] e0 fd [2] fc fa [2] e0 d5 }

  condition:
    any of them
}