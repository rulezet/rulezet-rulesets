rule TTP_XOR_QUAD_CurrentVersionRun_8b5d {
  strings:
    $key_8b5d = { d8 32 [2] fc 3c [2] d7 10 [2] f9 32 [2] ed 29 [2] e2 33 [2] fc 2e [2] fe 2f [2] e5 29 [2] f9 2e [2] e5 01 }

  condition:
    any of them
}