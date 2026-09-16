rule TTP_XOR_QUAD_CurrentVersionRun_967c {
  strings:
    $key_967c = { c5 13 [2] e1 1d [2] ca 31 [2] e4 13 [2] f0 08 [2] ff 12 [2] e1 0f [2] e3 0e [2] f8 08 [2] e4 0f [2] f8 20 }

  condition:
    any of them
}