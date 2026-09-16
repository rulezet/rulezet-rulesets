rule TTP_XOR_QUAD_CurrentVersionRun_8896 {
  strings:
    $key_8896 = { db f9 [2] ff f7 [2] d4 db [2] fa f9 [2] ee e2 [2] e1 f8 [2] ff e5 [2] fd e4 [2] e6 e2 [2] fa e5 [2] e6 ca }

  condition:
    any of them
}