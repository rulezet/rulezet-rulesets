rule TTP_XOR_QUAD_CurrentVersionRun_904a {
  strings:
    $key_904a = { c3 25 [2] e7 2b [2] cc 07 [2] e2 25 [2] f6 3e [2] f9 24 [2] e7 39 [2] e5 38 [2] fe 3e [2] e2 39 [2] fe 16 }

  condition:
    any of them
}