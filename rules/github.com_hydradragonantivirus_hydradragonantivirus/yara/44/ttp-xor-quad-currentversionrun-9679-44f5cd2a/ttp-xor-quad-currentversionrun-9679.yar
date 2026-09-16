rule TTP_XOR_QUAD_CurrentVersionRun_9679 {
  strings:
    $key_9679 = { c5 16 [2] e1 18 [2] ca 34 [2] e4 16 [2] f0 0d [2] ff 17 [2] e1 0a [2] e3 0b [2] f8 0d [2] e4 0a [2] f8 25 }

  condition:
    any of them
}