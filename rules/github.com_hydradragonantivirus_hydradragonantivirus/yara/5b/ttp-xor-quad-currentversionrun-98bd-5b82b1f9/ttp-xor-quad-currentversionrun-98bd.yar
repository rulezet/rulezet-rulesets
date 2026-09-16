rule TTP_XOR_QUAD_CurrentVersionRun_98bd {
  strings:
    $key_98bd = { cb d2 [2] ef dc [2] c4 f0 [2] ea d2 [2] fe c9 [2] f1 d3 [2] ef ce [2] ed cf [2] f6 c9 [2] ea ce [2] f6 e1 }

  condition:
    any of them
}