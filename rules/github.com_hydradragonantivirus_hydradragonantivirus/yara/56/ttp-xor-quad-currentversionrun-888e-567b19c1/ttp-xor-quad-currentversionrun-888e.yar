rule TTP_XOR_QUAD_CurrentVersionRun_888e {
  strings:
    $key_888e = { db e1 [2] ff ef [2] d4 c3 [2] fa e1 [2] ee fa [2] e1 e0 [2] ff fd [2] fd fc [2] e6 fa [2] fa fd [2] e6 d2 }

  condition:
    any of them
}