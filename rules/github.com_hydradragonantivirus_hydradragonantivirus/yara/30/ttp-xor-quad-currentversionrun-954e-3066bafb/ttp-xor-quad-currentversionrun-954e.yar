rule TTP_XOR_QUAD_CurrentVersionRun_954e {
  strings:
    $key_954e = { c6 21 [2] e2 2f [2] c9 03 [2] e7 21 [2] f3 3a [2] fc 20 [2] e2 3d [2] e0 3c [2] fb 3a [2] e7 3d [2] fb 12 }

  condition:
    any of them
}