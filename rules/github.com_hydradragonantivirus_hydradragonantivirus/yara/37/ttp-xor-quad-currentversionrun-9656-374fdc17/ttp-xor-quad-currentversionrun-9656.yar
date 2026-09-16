rule TTP_XOR_QUAD_CurrentVersionRun_9656 {
  strings:
    $key_9656 = { c5 39 [2] e1 37 [2] ca 1b [2] e4 39 [2] f0 22 [2] ff 38 [2] e1 25 [2] e3 24 [2] f8 22 [2] e4 25 [2] f8 0a }

  condition:
    any of them
}