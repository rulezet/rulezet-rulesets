rule TTP_XOR_QUAD_CurrentVersionRun_8bfa {
  strings:
    $key_8bfa = { d8 95 [2] fc 9b [2] d7 b7 [2] f9 95 [2] ed 8e [2] e2 94 [2] fc 89 [2] fe 88 [2] e5 8e [2] f9 89 [2] e5 a6 }

  condition:
    any of them
}