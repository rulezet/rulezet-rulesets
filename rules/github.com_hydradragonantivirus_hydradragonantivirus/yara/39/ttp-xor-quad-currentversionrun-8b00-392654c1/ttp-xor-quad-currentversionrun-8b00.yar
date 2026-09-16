rule TTP_XOR_QUAD_CurrentVersionRun_8b00 {
  strings:
    $key_8b00 = { d8 6f [2] fc 61 [2] d7 4d [2] f9 6f [2] ed 74 [2] e2 6e [2] fc 73 [2] fe 72 [2] e5 74 [2] f9 73 [2] e5 5c }

  condition:
    any of them
}