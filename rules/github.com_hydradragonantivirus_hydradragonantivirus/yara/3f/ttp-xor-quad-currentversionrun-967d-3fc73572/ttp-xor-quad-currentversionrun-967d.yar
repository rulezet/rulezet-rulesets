rule TTP_XOR_QUAD_CurrentVersionRun_967d {
  strings:
    $key_967d = { c5 12 [2] e1 1c [2] ca 30 [2] e4 12 [2] f0 09 [2] ff 13 [2] e1 0e [2] e3 0f [2] f8 09 [2] e4 0e [2] f8 21 }

  condition:
    any of them
}