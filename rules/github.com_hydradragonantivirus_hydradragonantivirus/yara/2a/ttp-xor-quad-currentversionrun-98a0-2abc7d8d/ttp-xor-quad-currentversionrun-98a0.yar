rule TTP_XOR_QUAD_CurrentVersionRun_98a0 {
  strings:
    $key_98a0 = { cb cf [2] ef c1 [2] c4 ed [2] ea cf [2] fe d4 [2] f1 ce [2] ef d3 [2] ed d2 [2] f6 d4 [2] ea d3 [2] f6 fc }

  condition:
    any of them
}