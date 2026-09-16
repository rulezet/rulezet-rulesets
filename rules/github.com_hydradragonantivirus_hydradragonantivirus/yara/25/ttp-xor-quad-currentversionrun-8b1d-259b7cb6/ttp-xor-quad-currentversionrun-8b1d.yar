rule TTP_XOR_QUAD_CurrentVersionRun_8b1d {
  strings:
    $key_8b1d = { d8 72 [2] fc 7c [2] d7 50 [2] f9 72 [2] ed 69 [2] e2 73 [2] fc 6e [2] fe 6f [2] e5 69 [2] f9 6e [2] e5 41 }

  condition:
    any of them
}