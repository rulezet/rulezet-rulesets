rule TTP_XOR_QUAD_CurrentVersionRun_8b37 {
  strings:
    $key_8b37 = { d8 58 [2] fc 56 [2] d7 7a [2] f9 58 [2] ed 43 [2] e2 59 [2] fc 44 [2] fe 45 [2] e5 43 [2] f9 44 [2] e5 6b }

  condition:
    any of them
}