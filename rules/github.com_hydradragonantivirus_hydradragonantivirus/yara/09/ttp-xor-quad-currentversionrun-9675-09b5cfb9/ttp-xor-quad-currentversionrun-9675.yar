rule TTP_XOR_QUAD_CurrentVersionRun_9675 {
  strings:
    $key_9675 = { c5 1a [2] e1 14 [2] ca 38 [2] e4 1a [2] f0 01 [2] ff 1b [2] e1 06 [2] e3 07 [2] f8 01 [2] e4 06 [2] f8 29 }

  condition:
    any of them
}