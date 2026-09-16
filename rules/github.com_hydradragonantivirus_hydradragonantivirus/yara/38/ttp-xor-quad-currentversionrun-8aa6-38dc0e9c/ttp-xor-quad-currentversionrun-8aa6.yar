rule TTP_XOR_QUAD_CurrentVersionRun_8aa6 {
  strings:
    $key_8aa6 = { d9 c9 [2] fd c7 [2] d6 eb [2] f8 c9 [2] ec d2 [2] e3 c8 [2] fd d5 [2] ff d4 [2] e4 d2 [2] f8 d5 [2] e4 fa }

  condition:
    any of them
}