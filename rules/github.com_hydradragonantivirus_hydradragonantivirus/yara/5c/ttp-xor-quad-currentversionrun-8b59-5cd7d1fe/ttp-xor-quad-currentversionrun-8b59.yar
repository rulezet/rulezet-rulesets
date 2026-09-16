rule TTP_XOR_QUAD_CurrentVersionRun_8b59 {
  strings:
    $key_8b59 = { d8 36 [2] fc 38 [2] d7 14 [2] f9 36 [2] ed 2d [2] e2 37 [2] fc 2a [2] fe 2b [2] e5 2d [2] f9 2a [2] e5 05 }

  condition:
    any of them
}