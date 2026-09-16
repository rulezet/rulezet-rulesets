rule TTP_XOR_QUAD_CurrentVersionRun_9fb8 {
  strings:
    $key_9fb8 = { cc d7 [2] e8 d9 [2] c3 f5 [2] ed d7 [2] f9 cc [2] f6 d6 [2] e8 cb [2] ea ca [2] f1 cc [2] ed cb [2] f1 e4 }

  condition:
    any of them
}