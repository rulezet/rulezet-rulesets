rule TTP_XOR_QUAD_CurrentVersionRun_9610 {
  strings:
    $key_9610 = { c5 7f [2] e1 71 [2] ca 5d [2] e4 7f [2] f0 64 [2] ff 7e [2] e1 63 [2] e3 62 [2] f8 64 [2] e4 63 [2] f8 4c }

  condition:
    any of them
}