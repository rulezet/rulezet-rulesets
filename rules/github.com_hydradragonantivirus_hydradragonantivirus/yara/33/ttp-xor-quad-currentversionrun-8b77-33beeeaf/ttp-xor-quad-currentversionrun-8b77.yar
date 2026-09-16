rule TTP_XOR_QUAD_CurrentVersionRun_8b77 {
  strings:
    $key_8b77 = { d8 18 [2] fc 16 [2] d7 3a [2] f9 18 [2] ed 03 [2] e2 19 [2] fc 04 [2] fe 05 [2] e5 03 [2] f9 04 [2] e5 2b }

  condition:
    any of them
}