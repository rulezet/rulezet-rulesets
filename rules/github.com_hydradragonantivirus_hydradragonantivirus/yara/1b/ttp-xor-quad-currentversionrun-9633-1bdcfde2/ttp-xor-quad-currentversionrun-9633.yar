rule TTP_XOR_QUAD_CurrentVersionRun_9633 {
  strings:
    $key_9633 = { c5 5c [2] e1 52 [2] ca 7e [2] e4 5c [2] f0 47 [2] ff 5d [2] e1 40 [2] e3 41 [2] f8 47 [2] e4 40 [2] f8 6f }

  condition:
    any of them
}