rule TTP_XOR_QUAD_CurrentVersionRun_900a {
  strings:
    $key_900a = { c3 65 [2] e7 6b [2] cc 47 [2] e2 65 [2] f6 7e [2] f9 64 [2] e7 79 [2] e5 78 [2] fe 7e [2] e2 79 [2] fe 56 }

  condition:
    any of them
}