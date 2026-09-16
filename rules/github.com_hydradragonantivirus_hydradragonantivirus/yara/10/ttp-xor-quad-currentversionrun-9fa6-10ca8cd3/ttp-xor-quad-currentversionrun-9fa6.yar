rule TTP_XOR_QUAD_CurrentVersionRun_9fa6 {
  strings:
    $key_9fa6 = { cc c9 [2] e8 c7 [2] c3 eb [2] ed c9 [2] f9 d2 [2] f6 c8 [2] e8 d5 [2] ea d4 [2] f1 d2 [2] ed d5 [2] f1 fa }

  condition:
    any of them
}