rule TTP_XOR_QUAD_CurrentVersionRun_9ba5 {
  strings:
    $key_9ba5 = { c8 ca [2] ec c4 [2] c7 e8 [2] e9 ca [2] fd d1 [2] f2 cb [2] ec d6 [2] ee d7 [2] f5 d1 [2] e9 d6 [2] f5 f9 }

  condition:
    any of them
}