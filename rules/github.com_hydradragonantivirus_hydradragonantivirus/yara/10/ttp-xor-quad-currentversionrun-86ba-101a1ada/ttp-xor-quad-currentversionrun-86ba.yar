rule TTP_XOR_QUAD_CurrentVersionRun_86ba {
  strings:
    $key_86ba = { d5 d5 [2] f1 db [2] da f7 [2] f4 d5 [2] e0 ce [2] ef d4 [2] f1 c9 [2] f3 c8 [2] e8 ce [2] f4 c9 [2] e8 e6 }

  condition:
    any of them
}