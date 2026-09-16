rule TTP_XOR_QUAD_CurrentVersionRun_8b0a {
  strings:
    $key_8b0a = { d8 65 [2] fc 6b [2] d7 47 [2] f9 65 [2] ed 7e [2] e2 64 [2] fc 79 [2] fe 78 [2] e5 7e [2] f9 79 [2] e5 56 }

  condition:
    any of them
}