rule TTP_XOR_QUAD_CurrentVersionRun_9672 {
  strings:
    $key_9672 = { c5 1d [2] e1 13 [2] ca 3f [2] e4 1d [2] f0 06 [2] ff 1c [2] e1 01 [2] e3 00 [2] f8 06 [2] e4 01 [2] f8 2e }

  condition:
    any of them
}