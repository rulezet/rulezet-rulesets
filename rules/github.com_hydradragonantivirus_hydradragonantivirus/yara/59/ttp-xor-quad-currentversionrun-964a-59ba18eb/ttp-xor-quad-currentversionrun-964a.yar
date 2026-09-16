rule TTP_XOR_QUAD_CurrentVersionRun_964a {
  strings:
    $key_964a = { c5 25 [2] e1 2b [2] ca 07 [2] e4 25 [2] f0 3e [2] ff 24 [2] e1 39 [2] e3 38 [2] f8 3e [2] e4 39 [2] f8 16 }

  condition:
    any of them
}