rule TTP_XOR_QUAD_CurrentVersionRun_8b5b {
  strings:
    $key_8b5b = { d8 34 [2] fc 3a [2] d7 16 [2] f9 34 [2] ed 2f [2] e2 35 [2] fc 28 [2] fe 29 [2] e5 2f [2] f9 28 [2] e5 07 }

  condition:
    any of them
}