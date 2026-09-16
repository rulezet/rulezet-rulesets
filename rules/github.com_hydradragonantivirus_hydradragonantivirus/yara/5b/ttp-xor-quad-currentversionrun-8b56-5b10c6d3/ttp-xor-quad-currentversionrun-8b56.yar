rule TTP_XOR_QUAD_CurrentVersionRun_8b56 {
  strings:
    $key_8b56 = { d8 39 [2] fc 37 [2] d7 1b [2] f9 39 [2] ed 22 [2] e2 38 [2] fc 25 [2] fe 24 [2] e5 22 [2] f9 25 [2] e5 0a }

  condition:
    any of them
}