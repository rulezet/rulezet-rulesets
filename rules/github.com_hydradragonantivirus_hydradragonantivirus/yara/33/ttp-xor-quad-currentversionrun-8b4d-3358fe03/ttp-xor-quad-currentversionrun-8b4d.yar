rule TTP_XOR_QUAD_CurrentVersionRun_8b4d {
  strings:
    $key_8b4d = { d8 22 [2] fc 2c [2] d7 00 [2] f9 22 [2] ed 39 [2] e2 23 [2] fc 3e [2] fe 3f [2] e5 39 [2] f9 3e [2] e5 11 }

  condition:
    any of them
}