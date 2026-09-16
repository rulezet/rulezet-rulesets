rule TTP_XOR_QUAD_CurrentVersionRun_8b63 {
  strings:
    $key_8b63 = { d8 0c [2] fc 02 [2] d7 2e [2] f9 0c [2] ed 17 [2] e2 0d [2] fc 10 [2] fe 11 [2] e5 17 [2] f9 10 [2] e5 3f }

  condition:
    any of them
}