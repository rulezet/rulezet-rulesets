rule TTP_XOR_QUAD_CurrentVersionRun_8b29 {
  strings:
    $key_8b29 = { d8 46 [2] fc 48 [2] d7 64 [2] f9 46 [2] ed 5d [2] e2 47 [2] fc 5a [2] fe 5b [2] e5 5d [2] f9 5a [2] e5 75 }

  condition:
    any of them
}