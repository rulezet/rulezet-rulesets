rule TTP_XOR_QUAD_CurrentVersionRun_924a {
  strings:
    $key_924a = { c1 25 [2] e5 2b [2] ce 07 [2] e0 25 [2] f4 3e [2] fb 24 [2] e5 39 [2] e7 38 [2] fc 3e [2] e0 39 [2] fc 16 }

  condition:
    any of them
}