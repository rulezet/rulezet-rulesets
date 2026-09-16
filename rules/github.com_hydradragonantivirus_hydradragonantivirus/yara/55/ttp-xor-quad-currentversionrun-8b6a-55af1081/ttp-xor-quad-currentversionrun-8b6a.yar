rule TTP_XOR_QUAD_CurrentVersionRun_8b6a {
  strings:
    $key_8b6a = { d8 05 [2] fc 0b [2] d7 27 [2] f9 05 [2] ed 1e [2] e2 04 [2] fc 19 [2] fe 18 [2] e5 1e [2] f9 19 [2] e5 36 }

  condition:
    any of them
}