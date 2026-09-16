rule TTP_XOR_QUAD_CurrentVersionRun_88aa {
  strings:
    $key_88aa = { db c5 [2] ff cb [2] d4 e7 [2] fa c5 [2] ee de [2] e1 c4 [2] ff d9 [2] fd d8 [2] e6 de [2] fa d9 [2] e6 f6 }

  condition:
    any of them
}