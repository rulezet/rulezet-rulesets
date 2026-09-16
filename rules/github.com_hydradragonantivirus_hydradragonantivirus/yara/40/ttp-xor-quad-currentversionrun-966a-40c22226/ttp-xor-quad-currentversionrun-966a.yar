rule TTP_XOR_QUAD_CurrentVersionRun_966a {
  strings:
    $key_966a = { c5 05 [2] e1 0b [2] ca 27 [2] e4 05 [2] f0 1e [2] ff 04 [2] e1 19 [2] e3 18 [2] f8 1e [2] e4 19 [2] f8 36 }

  condition:
    any of them
}