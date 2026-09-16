rule TTP_XOR_QUAD_CurrentVersionRun_920a {
  strings:
    $key_920a = { c1 65 [2] e5 6b [2] ce 47 [2] e0 65 [2] f4 7e [2] fb 64 [2] e5 79 [2] e7 78 [2] fc 7e [2] e0 79 [2] fc 56 }

  condition:
    any of them
}