rule TTP_XOR_QUAD_CurrentVersionRun_8889 {
  strings:
    $key_8889 = { db e6 [2] ff e8 [2] d4 c4 [2] fa e6 [2] ee fd [2] e1 e7 [2] ff fa [2] fd fb [2] e6 fd [2] fa fa [2] e6 d5 }

  condition:
    any of them
}