rule TTP_XOR_QUAD_CurrentVersionRun_88b5 {
  strings:
    $key_88b5 = { db da [2] ff d4 [2] d4 f8 [2] fa da [2] ee c1 [2] e1 db [2] ff c6 [2] fd c7 [2] e6 c1 [2] fa c6 [2] e6 e9 }

  condition:
    any of them
}