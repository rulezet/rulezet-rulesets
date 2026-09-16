rule TTP_XOR_QUAD_CurrentVersionRun_80ba {
  strings:
    $key_80ba = { d3 d5 [2] f7 db [2] dc f7 [2] f2 d5 [2] e6 ce [2] e9 d4 [2] f7 c9 [2] f5 c8 [2] ee ce [2] f2 c9 [2] ee e6 }

  condition:
    any of them
}