rule TTP_XOR_QUAD_CurrentVersionRun_849d {
  strings:
    $key_849d = { d7 f2 [2] f3 fc [2] d8 d0 [2] f6 f2 [2] e2 e9 [2] ed f3 [2] f3 ee [2] f1 ef [2] ea e9 [2] f6 ee [2] ea c1 }

  condition:
    any of them
}