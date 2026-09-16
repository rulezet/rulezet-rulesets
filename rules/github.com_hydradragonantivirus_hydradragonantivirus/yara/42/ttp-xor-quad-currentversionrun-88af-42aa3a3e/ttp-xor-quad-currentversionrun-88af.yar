rule TTP_XOR_QUAD_CurrentVersionRun_88af {
  strings:
    $key_88af = { db c0 [2] ff ce [2] d4 e2 [2] fa c0 [2] ee db [2] e1 c1 [2] ff dc [2] fd dd [2] e6 db [2] fa dc [2] e6 f3 }

  condition:
    any of them
}