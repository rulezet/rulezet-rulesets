rule TTP_XOR_QUAD_CurrentVersionRun_8b50 {
  strings:
    $key_8b50 = { d8 3f [2] fc 31 [2] d7 1d [2] f9 3f [2] ed 24 [2] e2 3e [2] fc 23 [2] fe 22 [2] e5 24 [2] f9 23 [2] e5 0c }

  condition:
    any of them
}