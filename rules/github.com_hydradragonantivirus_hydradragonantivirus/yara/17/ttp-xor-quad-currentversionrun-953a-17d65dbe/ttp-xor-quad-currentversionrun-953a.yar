rule TTP_XOR_QUAD_CurrentVersionRun_953a {
  strings:
    $key_953a = { c6 55 [2] e2 5b [2] c9 77 [2] e7 55 [2] f3 4e [2] fc 54 [2] e2 49 [2] e0 48 [2] fb 4e [2] e7 49 [2] fb 66 }

  condition:
    any of them
}