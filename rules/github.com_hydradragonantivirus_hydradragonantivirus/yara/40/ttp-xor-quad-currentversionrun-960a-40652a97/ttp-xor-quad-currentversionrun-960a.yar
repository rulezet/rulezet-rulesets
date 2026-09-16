rule TTP_XOR_QUAD_CurrentVersionRun_960a {
  strings:
    $key_960a = { c5 65 [2] e1 6b [2] ca 47 [2] e4 65 [2] f0 7e [2] ff 64 [2] e1 79 [2] e3 78 [2] f8 7e [2] e4 79 [2] f8 56 }

  condition:
    any of them
}