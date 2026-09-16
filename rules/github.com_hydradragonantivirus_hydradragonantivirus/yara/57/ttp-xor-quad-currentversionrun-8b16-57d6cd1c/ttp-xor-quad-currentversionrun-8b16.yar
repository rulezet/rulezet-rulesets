rule TTP_XOR_QUAD_CurrentVersionRun_8b16 {
  strings:
    $key_8b16 = { d8 79 [2] fc 77 [2] d7 5b [2] f9 79 [2] ed 62 [2] e2 78 [2] fc 65 [2] fe 64 [2] e5 62 [2] f9 65 [2] e5 4a }

  condition:
    any of them
}