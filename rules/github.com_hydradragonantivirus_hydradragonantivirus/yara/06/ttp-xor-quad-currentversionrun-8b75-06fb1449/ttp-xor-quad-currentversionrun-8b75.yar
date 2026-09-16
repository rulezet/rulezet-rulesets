rule TTP_XOR_QUAD_CurrentVersionRun_8b75 {
  strings:
    $key_8b75 = { d8 1a [2] fc 14 [2] d7 38 [2] f9 1a [2] ed 01 [2] e2 1b [2] fc 06 [2] fe 07 [2] e5 01 [2] f9 06 [2] e5 29 }

  condition:
    any of them
}