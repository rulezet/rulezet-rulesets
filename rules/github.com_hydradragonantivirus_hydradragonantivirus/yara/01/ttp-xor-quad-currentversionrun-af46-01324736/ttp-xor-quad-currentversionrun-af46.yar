rule TTP_XOR_QUAD_CurrentVersionRun_af46 {
  strings:
    $key_af46 = { fc 29 [2] d8 27 [2] f3 0b [2] dd 29 [2] c9 32 [2] c6 28 [2] d8 35 [2] da 34 [2] c1 32 [2] dd 35 [2] c1 1a }

  condition:
    any of them
}