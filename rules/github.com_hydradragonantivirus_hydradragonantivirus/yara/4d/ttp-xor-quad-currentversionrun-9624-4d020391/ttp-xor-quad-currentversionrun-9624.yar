rule TTP_XOR_QUAD_CurrentVersionRun_9624 {
  strings:
    $key_9624 = { c5 4b [2] e1 45 [2] ca 69 [2] e4 4b [2] f0 50 [2] ff 4a [2] e1 57 [2] e3 56 [2] f8 50 [2] e4 57 [2] f8 78 }

  condition:
    any of them
}