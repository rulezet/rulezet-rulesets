rule TTP_XOR_QUAD_CurrentVersionRun_925e {
  strings:
    $key_925e = { c1 31 [2] e5 3f [2] ce 13 [2] e0 31 [2] f4 2a [2] fb 30 [2] e5 2d [2] e7 2c [2] fc 2a [2] e0 2d [2] fc 02 }

  condition:
    any of them
}