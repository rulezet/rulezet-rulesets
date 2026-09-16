rule TTP_XOR_QUAD_CurrentVersionRun_8b17 {
  strings:
    $key_8b17 = { d8 78 [2] fc 76 [2] d7 5a [2] f9 78 [2] ed 63 [2] e2 79 [2] fc 64 [2] fe 65 [2] e5 63 [2] f9 64 [2] e5 4b }

  condition:
    any of them
}