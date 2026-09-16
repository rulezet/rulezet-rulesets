rule TTP_XOR_QUAD_CurrentVersionRun_8b23 {
  strings:
    $key_8b23 = { d8 4c [2] fc 42 [2] d7 6e [2] f9 4c [2] ed 57 [2] e2 4d [2] fc 50 [2] fe 51 [2] e5 57 [2] f9 50 [2] e5 7f }

  condition:
    any of them
}