rule TTP_XOR_QUAD_CurrentVersionRun_9645 {
  strings:
    $key_9645 = { c5 2a [2] e1 24 [2] ca 08 [2] e4 2a [2] f0 31 [2] ff 2b [2] e1 36 [2] e3 37 [2] f8 31 [2] e4 36 [2] f8 19 }

  condition:
    any of them
}