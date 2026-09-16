rule TTP_XOR_QUAD_CurrentVersionRun_955c {
  strings:
    $key_955c = { c6 33 [2] e2 3d [2] c9 11 [2] e7 33 [2] f3 28 [2] fc 32 [2] e2 2f [2] e0 2e [2] fb 28 [2] e7 2f [2] fb 00 }

  condition:
    any of them
}