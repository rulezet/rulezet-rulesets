rule TTP_XOR_QUAD_CurrentVersionRun_8ab6 {
  strings:
    $key_8ab6 = { d9 d9 [2] fd d7 [2] d6 fb [2] f8 d9 [2] ec c2 [2] e3 d8 [2] fd c5 [2] ff c4 [2] e4 c2 [2] f8 c5 [2] e4 ea }

  condition:
    any of them
}