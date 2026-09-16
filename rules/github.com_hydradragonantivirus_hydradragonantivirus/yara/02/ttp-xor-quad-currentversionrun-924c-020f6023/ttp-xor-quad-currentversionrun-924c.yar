rule TTP_XOR_QUAD_CurrentVersionRun_924c {
  strings:
    $key_924c = { c1 23 [2] e5 2d [2] ce 01 [2] e0 23 [2] f4 38 [2] fb 22 [2] e5 3f [2] e7 3e [2] fc 38 [2] e0 3f [2] fc 10 }

  condition:
    any of them
}