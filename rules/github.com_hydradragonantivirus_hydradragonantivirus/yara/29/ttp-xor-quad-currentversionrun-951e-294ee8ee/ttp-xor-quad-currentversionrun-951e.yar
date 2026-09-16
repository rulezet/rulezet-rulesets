rule TTP_XOR_QUAD_CurrentVersionRun_951e {
  strings:
    $key_951e = { c6 71 [2] e2 7f [2] c9 53 [2] e7 71 [2] f3 6a [2] fc 70 [2] e2 6d [2] e0 6c [2] fb 6a [2] e7 6d [2] fb 42 }

  condition:
    any of them
}