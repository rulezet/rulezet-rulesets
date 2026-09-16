rule TTP_XOR_QUAD_CurrentVersionRun_9661 {
  strings:
    $key_9661 = { c5 0e [2] e1 00 [2] ca 2c [2] e4 0e [2] f0 15 [2] ff 0f [2] e1 12 [2] e3 13 [2] f8 15 [2] e4 12 [2] f8 3d }

  condition:
    any of them
}