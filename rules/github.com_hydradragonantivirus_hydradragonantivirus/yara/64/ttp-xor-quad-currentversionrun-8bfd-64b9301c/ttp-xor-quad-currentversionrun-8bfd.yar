rule TTP_XOR_QUAD_CurrentVersionRun_8bfd {
  strings:
    $key_8bfd = { d8 92 [2] fc 9c [2] d7 b0 [2] f9 92 [2] ed 89 [2] e2 93 [2] fc 8e [2] fe 8f [2] e5 89 [2] f9 8e [2] e5 a1 }

  condition:
    any of them
}