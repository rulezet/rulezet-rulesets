rule TTP_XOR_QUAD_CurrentVersionRun_961a {
  strings:
    $key_961a = { c5 75 [2] e1 7b [2] ca 57 [2] e4 75 [2] f0 6e [2] ff 74 [2] e1 69 [2] e3 68 [2] f8 6e [2] e4 69 [2] f8 46 }

  condition:
    any of them
}