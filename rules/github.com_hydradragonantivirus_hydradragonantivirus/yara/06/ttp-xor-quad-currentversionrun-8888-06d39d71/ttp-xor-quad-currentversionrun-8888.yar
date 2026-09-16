rule TTP_XOR_QUAD_CurrentVersionRun_8888 {
  strings:
    $key_8888 = { db e7 [2] ff e9 [2] d4 c5 [2] fa e7 [2] ee fc [2] e1 e6 [2] ff fb [2] fd fa [2] e6 fc [2] fa fb [2] e6 d4 }

  condition:
    any of them
}