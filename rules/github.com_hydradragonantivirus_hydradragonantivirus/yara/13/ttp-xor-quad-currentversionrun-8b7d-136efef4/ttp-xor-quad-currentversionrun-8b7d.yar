rule TTP_XOR_QUAD_CurrentVersionRun_8b7d {
  strings:
    $key_8b7d = { d8 12 [2] fc 1c [2] d7 30 [2] f9 12 [2] ed 09 [2] e2 13 [2] fc 0e [2] fe 0f [2] e5 09 [2] f9 0e [2] e5 21 }

  condition:
    any of them
}