rule TTP_XOR_QUAD_CurrentVersionRun_954f {
  strings:
    $key_954f = { c6 20 [2] e2 2e [2] c9 02 [2] e7 20 [2] f3 3b [2] fc 21 [2] e2 3c [2] e0 3d [2] fb 3b [2] e7 3c [2] fb 13 }

  condition:
    any of them
}