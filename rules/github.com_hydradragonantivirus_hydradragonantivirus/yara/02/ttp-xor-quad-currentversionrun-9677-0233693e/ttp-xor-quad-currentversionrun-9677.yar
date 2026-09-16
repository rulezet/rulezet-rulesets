rule TTP_XOR_QUAD_CurrentVersionRun_9677 {
  strings:
    $key_9677 = { c5 18 [2] e1 16 [2] ca 3a [2] e4 18 [2] f0 03 [2] ff 19 [2] e1 04 [2] e3 05 [2] f8 03 [2] e4 04 [2] f8 2b }

  condition:
    any of them
}