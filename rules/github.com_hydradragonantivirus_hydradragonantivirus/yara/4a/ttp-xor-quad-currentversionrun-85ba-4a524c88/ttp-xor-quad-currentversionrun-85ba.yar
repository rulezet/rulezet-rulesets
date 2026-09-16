rule TTP_XOR_QUAD_CurrentVersionRun_85ba {
  strings:
    $key_85ba = { d6 d5 [2] f2 db [2] d9 f7 [2] f7 d5 [2] e3 ce [2] ec d4 [2] f2 c9 [2] f0 c8 [2] eb ce [2] f7 c9 [2] eb e6 }

  condition:
    any of them
}