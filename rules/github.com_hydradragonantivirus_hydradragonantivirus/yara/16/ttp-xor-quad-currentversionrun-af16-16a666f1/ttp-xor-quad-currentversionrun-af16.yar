rule TTP_XOR_QUAD_CurrentVersionRun_af16 {
  strings:
    $key_af16 = { fc 79 [2] d8 77 [2] f3 5b [2] dd 79 [2] c9 62 [2] c6 78 [2] d8 65 [2] da 64 [2] c1 62 [2] dd 65 [2] c1 4a }

  condition:
    any of them
}