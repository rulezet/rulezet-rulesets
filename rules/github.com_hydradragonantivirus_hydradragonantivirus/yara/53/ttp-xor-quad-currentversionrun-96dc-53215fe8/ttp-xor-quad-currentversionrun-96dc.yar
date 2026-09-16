rule TTP_XOR_QUAD_CurrentVersionRun_96dc {
  strings:
    $key_96dc = { c5 b3 [2] e1 bd [2] ca 91 [2] e4 b3 [2] f0 a8 [2] ff b2 [2] e1 af [2] e3 ae [2] f8 a8 [2] e4 af [2] f8 80 }

  condition:
    any of them
}