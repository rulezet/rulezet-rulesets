rule TTP_XOR_QUAD_CurrentVersionRun_88b8 {
  strings:
    $key_88b8 = { db d7 [2] ff d9 [2] d4 f5 [2] fa d7 [2] ee cc [2] e1 d6 [2] ff cb [2] fd ca [2] e6 cc [2] fa cb [2] e6 e4 }

  condition:
    any of them
}