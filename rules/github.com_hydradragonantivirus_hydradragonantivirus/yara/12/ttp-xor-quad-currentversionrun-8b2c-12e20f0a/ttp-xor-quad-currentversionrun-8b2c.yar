rule TTP_XOR_QUAD_CurrentVersionRun_8b2c {
  strings:
    $key_8b2c = { d8 43 [2] fc 4d [2] d7 61 [2] f9 43 [2] ed 58 [2] e2 42 [2] fc 5f [2] fe 5e [2] e5 58 [2] f9 5f [2] e5 70 }

  condition:
    any of them
}