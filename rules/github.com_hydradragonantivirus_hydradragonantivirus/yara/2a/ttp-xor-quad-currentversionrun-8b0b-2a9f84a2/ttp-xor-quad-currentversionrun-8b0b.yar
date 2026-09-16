rule TTP_XOR_QUAD_CurrentVersionRun_8b0b {
  strings:
    $key_8b0b = { d8 64 [2] fc 6a [2] d7 46 [2] f9 64 [2] ed 7f [2] e2 65 [2] fc 78 [2] fe 79 [2] e5 7f [2] f9 78 [2] e5 57 }

  condition:
    any of them
}