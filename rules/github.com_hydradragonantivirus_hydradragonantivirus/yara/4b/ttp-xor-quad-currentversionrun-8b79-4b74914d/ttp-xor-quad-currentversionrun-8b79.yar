rule TTP_XOR_QUAD_CurrentVersionRun_8b79 {
  strings:
    $key_8b79 = { d8 16 [2] fc 18 [2] d7 34 [2] f9 16 [2] ed 0d [2] e2 17 [2] fc 0a [2] fe 0b [2] e5 0d [2] f9 0a [2] e5 25 }

  condition:
    any of them
}