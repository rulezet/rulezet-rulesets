rule TTP_XOR_QUAD_CurrentVersionRun_8b06 {
  strings:
    $key_8b06 = { d8 69 [2] fc 67 [2] d7 4b [2] f9 69 [2] ed 72 [2] e2 68 [2] fc 75 [2] fe 74 [2] e5 72 [2] f9 75 [2] e5 5a }

  condition:
    any of them
}