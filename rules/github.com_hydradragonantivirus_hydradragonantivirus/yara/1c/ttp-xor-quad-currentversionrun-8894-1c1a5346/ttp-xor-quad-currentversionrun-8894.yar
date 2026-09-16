rule TTP_XOR_QUAD_CurrentVersionRun_8894 {
  strings:
    $key_8894 = { db fb [2] ff f5 [2] d4 d9 [2] fa fb [2] ee e0 [2] e1 fa [2] ff e7 [2] fd e6 [2] e6 e0 [2] fa e7 [2] e6 c8 }

  condition:
    any of them
}