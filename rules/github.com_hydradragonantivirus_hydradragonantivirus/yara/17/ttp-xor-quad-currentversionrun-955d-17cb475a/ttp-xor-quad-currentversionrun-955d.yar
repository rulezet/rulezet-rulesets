rule TTP_XOR_QUAD_CurrentVersionRun_955d {
  strings:
    $key_955d = { c6 32 [2] e2 3c [2] c9 10 [2] e7 32 [2] f3 29 [2] fc 33 [2] e2 2e [2] e0 2f [2] fb 29 [2] e7 2e [2] fb 01 }

  condition:
    any of them
}