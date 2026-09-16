rule TTP_XOR_QUAD_CurrentVersionRun_8b5c {
  strings:
    $key_8b5c = { d8 33 [2] fc 3d [2] d7 11 [2] f9 33 [2] ed 28 [2] e2 32 [2] fc 2f [2] fe 2e [2] e5 28 [2] f9 2f [2] e5 00 }

  condition:
    any of them
}