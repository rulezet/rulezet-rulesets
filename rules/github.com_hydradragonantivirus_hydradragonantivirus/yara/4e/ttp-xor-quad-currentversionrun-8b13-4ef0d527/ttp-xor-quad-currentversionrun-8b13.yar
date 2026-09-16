rule TTP_XOR_QUAD_CurrentVersionRun_8b13 {
  strings:
    $key_8b13 = { d8 7c [2] fc 72 [2] d7 5e [2] f9 7c [2] ed 67 [2] e2 7d [2] fc 60 [2] fe 61 [2] e5 67 [2] f9 60 [2] e5 4f }

  condition:
    any of them
}