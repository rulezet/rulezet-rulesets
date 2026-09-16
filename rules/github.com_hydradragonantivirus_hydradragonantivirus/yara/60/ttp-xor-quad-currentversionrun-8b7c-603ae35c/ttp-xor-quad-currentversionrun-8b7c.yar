rule TTP_XOR_QUAD_CurrentVersionRun_8b7c {
  strings:
    $key_8b7c = { d8 13 [2] fc 1d [2] d7 31 [2] f9 13 [2] ed 08 [2] e2 12 [2] fc 0f [2] fe 0e [2] e5 08 [2] f9 0f [2] e5 20 }

  condition:
    any of them
}