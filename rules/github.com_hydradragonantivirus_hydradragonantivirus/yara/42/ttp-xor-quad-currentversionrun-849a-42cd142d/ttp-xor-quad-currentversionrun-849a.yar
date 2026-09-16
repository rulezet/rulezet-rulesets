rule TTP_XOR_QUAD_CurrentVersionRun_849a {
  strings:
    $key_849a = { d7 f5 [2] f3 fb [2] d8 d7 [2] f6 f5 [2] e2 ee [2] ed f4 [2] f3 e9 [2] f1 e8 [2] ea ee [2] f6 e9 [2] ea c6 }

  condition:
    any of them
}