rule TTP_XOR_QUAD_CurrentVersionRun_922d {
  strings:
    $key_922d = { c1 42 [2] e5 4c [2] ce 60 [2] e0 42 [2] f4 59 [2] fb 43 [2] e5 5e [2] e7 5f [2] fc 59 [2] e0 5e [2] fc 71 }

  condition:
    any of them
}