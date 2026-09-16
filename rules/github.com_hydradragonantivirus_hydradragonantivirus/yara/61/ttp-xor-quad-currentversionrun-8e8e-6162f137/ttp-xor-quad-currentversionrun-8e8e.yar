rule TTP_XOR_QUAD_CurrentVersionRun_8e8e {
  strings:
    $key_8e8e = { dd e1 [2] f9 ef [2] d2 c3 [2] fc e1 [2] e8 fa [2] e7 e0 [2] f9 fd [2] fb fc [2] e0 fa [2] fc fd [2] e0 d2 }

  condition:
    any of them
}