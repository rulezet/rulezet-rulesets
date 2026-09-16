rule TTP_XOR_QUAD_CurrentVersionRun_8b44 {
  strings:
    $key_8b44 = { d8 2b [2] fc 25 [2] d7 09 [2] f9 2b [2] ed 30 [2] e2 2a [2] fc 37 [2] fe 36 [2] e5 30 [2] f9 37 [2] e5 18 }

  condition:
    any of them
}