rule TTP_XOR_QUAD_CurrentVersionRun_9fa0 {
  strings:
    $key_9fa0 = { cc cf [2] e8 c1 [2] c3 ed [2] ed cf [2] f9 d4 [2] f6 ce [2] e8 d3 [2] ea d2 [2] f1 d4 [2] ed d3 [2] f1 fc }

  condition:
    any of them
}