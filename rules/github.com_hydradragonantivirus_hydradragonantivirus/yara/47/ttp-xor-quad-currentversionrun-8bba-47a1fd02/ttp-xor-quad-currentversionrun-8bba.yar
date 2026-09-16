rule TTP_XOR_QUAD_CurrentVersionRun_8bba {
  strings:
    $key_8bba = { d8 d5 [2] fc db [2] d7 f7 [2] f9 d5 [2] ed ce [2] e2 d4 [2] fc c9 [2] fe c8 [2] e5 ce [2] f9 c9 [2] e5 e6 }

  condition:
    any of them
}