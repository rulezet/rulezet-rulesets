rule TTP_XOR_QUAD_CurrentVersionRun_9bb9 {
  strings:
    $key_9bb9 = { c8 d6 [2] ec d8 [2] c7 f4 [2] e9 d6 [2] fd cd [2] f2 d7 [2] ec ca [2] ee cb [2] f5 cd [2] e9 ca [2] f5 e5 }

  condition:
    any of them
}