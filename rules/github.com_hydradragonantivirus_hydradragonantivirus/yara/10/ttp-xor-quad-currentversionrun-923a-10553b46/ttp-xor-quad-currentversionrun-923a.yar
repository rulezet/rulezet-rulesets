rule TTP_XOR_QUAD_CurrentVersionRun_923a {
  strings:
    $key_923a = { c1 55 [2] e5 5b [2] ce 77 [2] e0 55 [2] f4 4e [2] fb 54 [2] e5 49 [2] e7 48 [2] fc 4e [2] e0 49 [2] fc 66 }

  condition:
    any of them
}