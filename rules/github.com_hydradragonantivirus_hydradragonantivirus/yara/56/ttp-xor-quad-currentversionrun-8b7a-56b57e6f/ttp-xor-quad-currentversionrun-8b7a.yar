rule TTP_XOR_QUAD_CurrentVersionRun_8b7a {
  strings:
    $key_8b7a = { d8 15 [2] fc 1b [2] d7 37 [2] f9 15 [2] ed 0e [2] e2 14 [2] fc 09 [2] fe 08 [2] e5 0e [2] f9 09 [2] e5 26 }

  condition:
    any of them
}