rule TTP_XOR_QUAD_CurrentVersionRun_85bf {
  strings:
    $key_85bf = { d6 d0 [2] f2 de [2] d9 f2 [2] f7 d0 [2] e3 cb [2] ec d1 [2] f2 cc [2] f0 cd [2] eb cb [2] f7 cc [2] eb e3 }

  condition:
    any of them
}