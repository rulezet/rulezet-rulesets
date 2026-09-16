rule TTP_XOR_QUAD_CurrentVersionRun_927c {
  strings:
    $key_927c = { c1 13 [2] e5 1d [2] ce 31 [2] e0 13 [2] f4 08 [2] fb 12 [2] e5 0f [2] e7 0e [2] fc 08 [2] e0 0f [2] fc 20 }

  condition:
    any of them
}