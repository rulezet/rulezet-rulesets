rule TTP_XOR_QUAD_CurrentVersionRun_926a {
  strings:
    $key_926a = { c1 05 [2] e5 0b [2] ce 27 [2] e0 05 [2] f4 1e [2] fb 04 [2] e5 19 [2] e7 18 [2] fc 1e [2] e0 19 [2] fc 36 }

  condition:
    any of them
}