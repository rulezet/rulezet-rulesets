rule TTP_XOR_QUAD_CurrentVersionRun_9baa {
  strings:
    $key_9baa = { c8 c5 [2] ec cb [2] c7 e7 [2] e9 c5 [2] fd de [2] f2 c4 [2] ec d9 [2] ee d8 [2] f5 de [2] e9 d9 [2] f5 f6 }

  condition:
    any of them
}