rule TTP_XOR_QUAD_CurrentVersionRun_8b2a {
  strings:
    $key_8b2a = { d8 45 [2] fc 4b [2] d7 67 [2] f9 45 [2] ed 5e [2] e2 44 [2] fc 59 [2] fe 58 [2] e5 5e [2] f9 59 [2] e5 76 }

  condition:
    any of them
}