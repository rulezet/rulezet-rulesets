rule TTP_XOR_QUAD_CurrentVersionRun_99ba {
  strings:
    $key_99ba = { ca d5 [2] ee db [2] c5 f7 [2] eb d5 [2] ff ce [2] f0 d4 [2] ee c9 [2] ec c8 [2] f7 ce [2] eb c9 [2] f7 e6 }

  condition:
    any of them
}