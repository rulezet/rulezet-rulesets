rule TTP_XOR_QUAD_CurrentVersionRun_8b4a {
  strings:
    $key_8b4a = { d8 25 [2] fc 2b [2] d7 07 [2] f9 25 [2] ed 3e [2] e2 24 [2] fc 39 [2] fe 38 [2] e5 3e [2] f9 39 [2] e5 16 }

  condition:
    any of them
}