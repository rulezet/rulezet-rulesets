rule TTP_XOR_QUAD_CurrentVersionRun_9641 {
  strings:
    $key_9641 = { c5 2e [2] e1 20 [2] ca 0c [2] e4 2e [2] f0 35 [2] ff 2f [2] e1 32 [2] e3 33 [2] f8 35 [2] e4 32 [2] f8 1d }

  condition:
    any of them
}