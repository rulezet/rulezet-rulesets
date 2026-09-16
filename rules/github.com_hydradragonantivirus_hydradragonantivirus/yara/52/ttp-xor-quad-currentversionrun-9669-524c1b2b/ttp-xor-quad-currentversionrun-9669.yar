rule TTP_XOR_QUAD_CurrentVersionRun_9669 {
  strings:
    $key_9669 = { c5 06 [2] e1 08 [2] ca 24 [2] e4 06 [2] f0 1d [2] ff 07 [2] e1 1a [2] e3 1b [2] f8 1d [2] e4 1a [2] f8 35 }

  condition:
    any of them
}