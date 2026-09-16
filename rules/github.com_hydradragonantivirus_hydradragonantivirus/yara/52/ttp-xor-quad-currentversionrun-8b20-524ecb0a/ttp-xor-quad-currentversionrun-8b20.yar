rule TTP_XOR_QUAD_CurrentVersionRun_8b20 {
  strings:
    $key_8b20 = { d8 4f [2] fc 41 [2] d7 6d [2] f9 4f [2] ed 54 [2] e2 4e [2] fc 53 [2] fe 52 [2] e5 54 [2] f9 53 [2] e5 7c }

  condition:
    any of them
}