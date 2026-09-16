rule TTP_XOR_QUAD_CurrentVersionRun_8ab7 {
  strings:
    $key_8ab7 = { d9 d8 [2] fd d6 [2] d6 fa [2] f8 d8 [2] ec c3 [2] e3 d9 [2] fd c4 [2] ff c5 [2] e4 c3 [2] f8 c4 [2] e4 eb }

  condition:
    any of them
}