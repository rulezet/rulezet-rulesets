rule TTP_XOR_QUAD_CurrentVersionRun_84bd {
  strings:
    $key_84bd = { d7 d2 [2] f3 dc [2] d8 f0 [2] f6 d2 [2] e2 c9 [2] ed d3 [2] f3 ce [2] f1 cf [2] ea c9 [2] f6 ce [2] ea e1 }

  condition:
    any of them
}