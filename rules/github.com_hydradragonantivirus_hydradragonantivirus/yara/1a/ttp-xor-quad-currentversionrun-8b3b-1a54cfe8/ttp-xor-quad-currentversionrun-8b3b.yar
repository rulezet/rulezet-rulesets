rule TTP_XOR_QUAD_CurrentVersionRun_8b3b {
  strings:
    $key_8b3b = { d8 54 [2] fc 5a [2] d7 76 [2] f9 54 [2] ed 4f [2] e2 55 [2] fc 48 [2] fe 49 [2] e5 4f [2] f9 48 [2] e5 67 }

  condition:
    any of them
}