rule TTP_XOR_QUAD_CurrentVersionRun_9626 {
  strings:
    $key_9626 = { c5 49 [2] e1 47 [2] ca 6b [2] e4 49 [2] f0 52 [2] ff 48 [2] e1 55 [2] e3 54 [2] f8 52 [2] e4 55 [2] f8 7a }

  condition:
    any of them
}