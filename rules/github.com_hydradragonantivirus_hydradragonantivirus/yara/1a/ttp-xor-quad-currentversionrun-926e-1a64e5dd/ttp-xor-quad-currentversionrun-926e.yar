rule TTP_XOR_QUAD_CurrentVersionRun_926e {
  strings:
    $key_926e = { c1 01 [2] e5 0f [2] ce 23 [2] e0 01 [2] f4 1a [2] fb 00 [2] e5 1d [2] e7 1c [2] fc 1a [2] e0 1d [2] fc 32 }

  condition:
    any of them
}