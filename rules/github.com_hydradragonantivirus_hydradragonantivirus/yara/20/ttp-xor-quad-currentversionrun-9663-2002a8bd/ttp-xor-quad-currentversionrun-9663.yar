rule TTP_XOR_QUAD_CurrentVersionRun_9663 {
  strings:
    $key_9663 = { c5 0c [2] e1 02 [2] ca 2e [2] e4 0c [2] f0 17 [2] ff 0d [2] e1 10 [2] e3 11 [2] f8 17 [2] e4 10 [2] f8 3f }

  condition:
    any of them
}