rule TTP_XOR_QUAD_CurrentVersionRun_9640 {
  strings:
    $key_9640 = { c5 2f [2] e1 21 [2] ca 0d [2] e4 2f [2] f0 34 [2] ff 2e [2] e1 33 [2] e3 32 [2] f8 34 [2] e4 33 [2] f8 1c }

  condition:
    any of them
}