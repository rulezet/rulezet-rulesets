rule TTP_XOR_QUAD_CurrentVersionRun_9bb8 {
  strings:
    $key_9bb8 = { c8 d7 [2] ec d9 [2] c7 f5 [2] e9 d7 [2] fd cc [2] f2 d6 [2] ec cb [2] ee ca [2] f5 cc [2] e9 cb [2] f5 e4 }

  condition:
    any of them
}