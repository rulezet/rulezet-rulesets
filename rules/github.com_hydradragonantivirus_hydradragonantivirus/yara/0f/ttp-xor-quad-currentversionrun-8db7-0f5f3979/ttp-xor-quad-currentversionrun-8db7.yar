rule TTP_XOR_QUAD_CurrentVersionRun_8db7 {
  strings:
    $key_8db7 = { de d8 [2] fa d6 [2] d1 fa [2] ff d8 [2] eb c3 [2] e4 d9 [2] fa c4 [2] f8 c5 [2] e3 c3 [2] ff c4 [2] e3 eb }

  condition:
    any of them
}