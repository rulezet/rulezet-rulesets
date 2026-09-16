rule TTP_XOR_QUAD_CurrentVersionRun_8b26 {
  strings:
    $key_8b26 = { d8 49 [2] fc 47 [2] d7 6b [2] f9 49 [2] ed 52 [2] e2 48 [2] fc 55 [2] fe 54 [2] e5 52 [2] f9 55 [2] e5 7a }

  condition:
    any of them
}