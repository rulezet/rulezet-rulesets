rule TTP_XOR_QUAD_CurrentVersionRun_849b {
  strings:
    $key_849b = { d7 f4 [2] f3 fa [2] d8 d6 [2] f6 f4 [2] e2 ef [2] ed f5 [2] f3 e8 [2] f1 e9 [2] ea ef [2] f6 e8 [2] ea c7 }

  condition:
    any of them
}