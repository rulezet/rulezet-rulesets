rule TTP_XOR_QUAD_CurrentVersionRun_88b7 {
  strings:
    $key_88b7 = { db d8 [2] ff d6 [2] d4 fa [2] fa d8 [2] ee c3 [2] e1 d9 [2] ff c4 [2] fd c5 [2] e6 c3 [2] fa c4 [2] e6 eb }

  condition:
    any of them
}