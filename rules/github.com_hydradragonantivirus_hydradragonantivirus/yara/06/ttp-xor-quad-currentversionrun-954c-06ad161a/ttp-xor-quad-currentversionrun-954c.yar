rule TTP_XOR_QUAD_CurrentVersionRun_954c {
  strings:
    $key_954c = { c6 23 [2] e2 2d [2] c9 01 [2] e7 23 [2] f3 38 [2] fc 22 [2] e2 3f [2] e0 3e [2] fb 38 [2] e7 3f [2] fb 10 }

  condition:
    any of them
}