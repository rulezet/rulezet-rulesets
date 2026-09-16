rule TTP_XOR_QUAD_CurrentVersionRun_927a {
  strings:
    $key_927a = { c1 15 [2] e5 1b [2] ce 37 [2] e0 15 [2] f4 0e [2] fb 14 [2] e5 09 [2] e7 08 [2] fc 0e [2] e0 09 [2] fc 26 }

  condition:
    any of them
}