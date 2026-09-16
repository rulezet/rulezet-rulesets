rule TTP_XOR_QUAD_CurrentVersionRun_9648 {
  strings:
    $key_9648 = { c5 27 [2] e1 29 [2] ca 05 [2] e4 27 [2] f0 3c [2] ff 26 [2] e1 3b [2] e3 3a [2] f8 3c [2] e4 3b [2] f8 14 }

  condition:
    any of them
}