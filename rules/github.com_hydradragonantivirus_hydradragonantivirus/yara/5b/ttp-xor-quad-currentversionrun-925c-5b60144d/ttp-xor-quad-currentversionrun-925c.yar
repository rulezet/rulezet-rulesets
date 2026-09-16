rule TTP_XOR_QUAD_CurrentVersionRun_925c {
  strings:
    $key_925c = { c1 33 [2] e5 3d [2] ce 11 [2] e0 33 [2] f4 28 [2] fb 32 [2] e5 2f [2] e7 2e [2] fc 28 [2] e0 2f [2] fc 00 }

  condition:
    any of them
}