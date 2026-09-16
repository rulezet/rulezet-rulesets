rule TTP_XOR_QUAD_CurrentVersionRun_8b5a {
  strings:
    $key_8b5a = { d8 35 [2] fc 3b [2] d7 17 [2] f9 35 [2] ed 2e [2] e2 34 [2] fc 29 [2] fe 28 [2] e5 2e [2] f9 29 [2] e5 06 }

  condition:
    any of them
}