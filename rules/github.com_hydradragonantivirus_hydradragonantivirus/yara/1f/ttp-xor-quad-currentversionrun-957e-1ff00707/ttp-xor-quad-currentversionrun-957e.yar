rule TTP_XOR_QUAD_CurrentVersionRun_957e {
  strings:
    $key_957e = { c6 11 [2] e2 1f [2] c9 33 [2] e7 11 [2] f3 0a [2] fc 10 [2] e2 0d [2] e0 0c [2] fb 0a [2] e7 0d [2] fb 22 }

  condition:
    any of them
}