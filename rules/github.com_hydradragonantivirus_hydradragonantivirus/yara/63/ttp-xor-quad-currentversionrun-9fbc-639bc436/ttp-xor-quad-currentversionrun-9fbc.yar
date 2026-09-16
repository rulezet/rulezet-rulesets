rule TTP_XOR_QUAD_CurrentVersionRun_9fbc {
  strings:
    $key_9fbc = { cc d3 [2] e8 dd [2] c3 f1 [2] ed d3 [2] f9 c8 [2] f6 d2 [2] e8 cf [2] ea ce [2] f1 c8 [2] ed cf [2] f1 e0 }

  condition:
    any of them
}