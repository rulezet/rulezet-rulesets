rule TTP_XOR_QUAD_CurrentVersionRun_964d {
  strings:
    $key_964d = { c5 22 [2] e1 2c [2] ca 00 [2] e4 22 [2] f0 39 [2] ff 23 [2] e1 3e [2] e3 3f [2] f8 39 [2] e4 3e [2] f8 11 }

  condition:
    any of them
}