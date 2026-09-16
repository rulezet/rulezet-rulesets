rule TTP_XOR_QUAD_CurrentVersionRun_9671 {
  strings:
    $key_9671 = { c5 1e [2] e1 10 [2] ca 3c [2] e4 1e [2] f0 05 [2] ff 1f [2] e1 02 [2] e3 03 [2] f8 05 [2] e4 02 [2] f8 2d }

  condition:
    any of them
}