rule TTP_XOR_QUAD_CurrentVersionRun_99b9 {
  strings:
    $key_99b9 = { ca d6 [2] ee d8 [2] c5 f4 [2] eb d6 [2] ff cd [2] f0 d7 [2] ee ca [2] ec cb [2] f7 cd [2] eb ca [2] f7 e5 }

  condition:
    any of them
}