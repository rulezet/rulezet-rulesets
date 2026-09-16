rule TTP_XOR_QUAD_CurrentVersionRun_9fc5 {
  strings:
    $key_9fc5 = { cc aa [2] e8 a4 [2] c3 88 [2] ed aa [2] f9 b1 [2] f6 ab [2] e8 b6 [2] ea b7 [2] f1 b1 [2] ed b6 [2] f1 99 }

  condition:
    any of them
}