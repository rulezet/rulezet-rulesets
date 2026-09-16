rule TTP_XOR_QUAD_CurrentVersionRun_926d {
  strings:
    $key_926d = { c1 02 [2] e5 0c [2] ce 20 [2] e0 02 [2] f4 19 [2] fb 03 [2] e5 1e [2] e7 1f [2] fc 19 [2] e0 1e [2] fc 31 }

  condition:
    any of them
}