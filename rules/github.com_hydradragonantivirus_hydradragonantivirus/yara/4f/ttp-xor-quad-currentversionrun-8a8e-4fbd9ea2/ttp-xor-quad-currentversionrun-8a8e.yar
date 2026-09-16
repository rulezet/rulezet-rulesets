rule TTP_XOR_QUAD_CurrentVersionRun_8a8e {
  strings:
    $key_8a8e = { d9 e1 [2] fd ef [2] d6 c3 [2] f8 e1 [2] ec fa [2] e3 e0 [2] fd fd [2] ff fc [2] e4 fa [2] f8 fd [2] e4 d2 }

  condition:
    any of them
}