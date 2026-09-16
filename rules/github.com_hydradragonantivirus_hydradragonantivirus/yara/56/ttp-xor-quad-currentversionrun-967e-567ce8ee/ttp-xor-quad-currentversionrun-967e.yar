rule TTP_XOR_QUAD_CurrentVersionRun_967e {
  strings:
    $key_967e = { c5 11 [2] e1 1f [2] ca 33 [2] e4 11 [2] f0 0a [2] ff 10 [2] e1 0d [2] e3 0c [2] f8 0a [2] e4 0d [2] f8 22 }

  condition:
    any of them
}