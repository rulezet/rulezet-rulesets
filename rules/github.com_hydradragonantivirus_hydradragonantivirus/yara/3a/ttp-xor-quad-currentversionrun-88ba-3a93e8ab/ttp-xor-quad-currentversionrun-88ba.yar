rule TTP_XOR_QUAD_CurrentVersionRun_88ba {
  strings:
    $key_88ba = { db d5 [2] ff db [2] d4 f7 [2] fa d5 [2] ee ce [2] e1 d4 [2] ff c9 [2] fd c8 [2] e6 ce [2] fa c9 [2] e6 e6 }

  condition:
    any of them
}