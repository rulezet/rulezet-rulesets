rule TTP_XOR_QUAD_CurrentVersionRun_8b39 {
  strings:
    $key_8b39 = { d8 56 [2] fc 58 [2] d7 74 [2] f9 56 [2] ed 4d [2] e2 57 [2] fc 4a [2] fe 4b [2] e5 4d [2] f9 4a [2] e5 65 }

  condition:
    any of them
}