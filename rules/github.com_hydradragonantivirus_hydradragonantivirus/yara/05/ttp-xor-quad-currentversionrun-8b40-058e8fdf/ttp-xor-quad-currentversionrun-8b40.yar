rule TTP_XOR_QUAD_CurrentVersionRun_8b40 {
  strings:
    $key_8b40 = { d8 2f [2] fc 21 [2] d7 0d [2] f9 2f [2] ed 34 [2] e2 2e [2] fc 33 [2] fe 32 [2] e5 34 [2] f9 33 [2] e5 1c }

  condition:
    any of them
}