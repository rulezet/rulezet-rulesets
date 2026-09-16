rule TTP_XOR_QUAD_CurrentVersionRun_8b30 {
  strings:
    $key_8b30 = { d8 5f [2] fc 51 [2] d7 7d [2] f9 5f [2] ed 44 [2] e2 5e [2] fc 43 [2] fe 42 [2] e5 44 [2] f9 43 [2] e5 6c }

  condition:
    any of them
}