rule TTP_XOR_QUAD_CurrentVersionRun_964b {
  strings:
    $key_964b = { c5 24 [2] e1 2a [2] ca 06 [2] e4 24 [2] f0 3f [2] ff 25 [2] e1 38 [2] e3 39 [2] f8 3f [2] e4 38 [2] f8 17 }

  condition:
    any of them
}