rule TTP_XOR_QUAD_CurrentVersionRun_8baa {
  strings:
    $key_8baa = { d8 c5 [2] fc cb [2] d7 e7 [2] f9 c5 [2] ed de [2] e2 c4 [2] fc d9 [2] fe d8 [2] e5 de [2] f9 d9 [2] e5 f6 }

  condition:
    any of them
}