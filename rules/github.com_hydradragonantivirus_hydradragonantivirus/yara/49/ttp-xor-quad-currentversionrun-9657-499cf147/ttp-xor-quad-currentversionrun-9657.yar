rule TTP_XOR_QUAD_CurrentVersionRun_9657 {
  strings:
    $key_9657 = { c5 38 [2] e1 36 [2] ca 1a [2] e4 38 [2] f0 23 [2] ff 39 [2] e1 24 [2] e3 25 [2] f8 23 [2] e4 24 [2] f8 0b }

  condition:
    any of them
}