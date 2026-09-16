rule TTP_XOR_QUAD_CurrentVersionRun_85b9 {
  strings:
    $key_85b9 = { d6 d6 [2] f2 d8 [2] d9 f4 [2] f7 d6 [2] e3 cd [2] ec d7 [2] f2 ca [2] f0 cb [2] eb cd [2] f7 ca [2] eb e5 }

  condition:
    any of them
}