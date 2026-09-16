rule TTP_XOR_QUAD_CurrentVersionRun_8891 {
  strings:
    $key_8891 = { db fe [2] ff f0 [2] d4 dc [2] fa fe [2] ee e5 [2] e1 ff [2] ff e2 [2] fd e3 [2] e6 e5 [2] fa e2 [2] e6 cd }

  condition:
    any of them
}