rule TTP_XOR_QUAD_CurrentVersionRun_8b60 {
  strings:
    $key_8b60 = { d8 0f [2] fc 01 [2] d7 2d [2] f9 0f [2] ed 14 [2] e2 0e [2] fc 13 [2] fe 12 [2] e5 14 [2] f9 13 [2] e5 3c }

  condition:
    any of them
}