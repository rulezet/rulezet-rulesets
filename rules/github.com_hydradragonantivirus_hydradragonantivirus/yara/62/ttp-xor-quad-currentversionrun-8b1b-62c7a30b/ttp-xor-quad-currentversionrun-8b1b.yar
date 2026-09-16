rule TTP_XOR_QUAD_CurrentVersionRun_8b1b {
  strings:
    $key_8b1b = { d8 74 [2] fc 7a [2] d7 56 [2] f9 74 [2] ed 6f [2] e2 75 [2] fc 68 [2] fe 69 [2] e5 6f [2] f9 68 [2] e5 47 }

  condition:
    any of them
}