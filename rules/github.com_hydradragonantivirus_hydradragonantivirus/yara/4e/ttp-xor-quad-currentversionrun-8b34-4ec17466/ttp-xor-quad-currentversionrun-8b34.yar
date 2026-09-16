rule TTP_XOR_QUAD_CurrentVersionRun_8b34 {
  strings:
    $key_8b34 = { d8 5b [2] fc 55 [2] d7 79 [2] f9 5b [2] ed 40 [2] e2 5a [2] fc 47 [2] fe 46 [2] e5 40 [2] f9 47 [2] e5 68 }

  condition:
    any of them
}