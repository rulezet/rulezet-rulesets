rule TTP_XOR_QUAD_CurrentVersionRun_8897 {
  strings:
    $key_8897 = { db f8 [2] ff f6 [2] d4 da [2] fa f8 [2] ee e3 [2] e1 f9 [2] ff e4 [2] fd e5 [2] e6 e3 [2] fa e4 [2] e6 cb }

  condition:
    any of them
}