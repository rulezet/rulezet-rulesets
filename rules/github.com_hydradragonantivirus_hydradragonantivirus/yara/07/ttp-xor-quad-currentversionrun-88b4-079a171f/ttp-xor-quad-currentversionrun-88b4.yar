rule TTP_XOR_QUAD_CurrentVersionRun_88b4 {
  strings:
    $key_88b4 = { db db [2] ff d5 [2] d4 f9 [2] fa db [2] ee c0 [2] e1 da [2] ff c7 [2] fd c6 [2] e6 c0 [2] fa c7 [2] e6 e8 }

  condition:
    any of them
}