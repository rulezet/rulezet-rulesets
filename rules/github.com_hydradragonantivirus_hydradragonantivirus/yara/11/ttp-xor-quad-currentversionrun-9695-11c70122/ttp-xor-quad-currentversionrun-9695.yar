rule TTP_XOR_QUAD_CurrentVersionRun_9695 {
  strings:
    $key_9695 = { c5 fa [2] e1 f4 [2] ca d8 [2] e4 fa [2] f0 e1 [2] ff fb [2] e1 e6 [2] e3 e7 [2] f8 e1 [2] e4 e6 [2] f8 c9 }

  condition:
    any of them
}