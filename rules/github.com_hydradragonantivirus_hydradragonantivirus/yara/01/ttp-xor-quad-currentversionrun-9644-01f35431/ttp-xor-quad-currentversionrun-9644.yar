rule TTP_XOR_QUAD_CurrentVersionRun_9644 {
  strings:
    $key_9644 = { c5 2b [2] e1 25 [2] ca 09 [2] e4 2b [2] f0 30 [2] ff 2a [2] e1 37 [2] e3 36 [2] f8 30 [2] e4 37 [2] f8 18 }

  condition:
    any of them
}