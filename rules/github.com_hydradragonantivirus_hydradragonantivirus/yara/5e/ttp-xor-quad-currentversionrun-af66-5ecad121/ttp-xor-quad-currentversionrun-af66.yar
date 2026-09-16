rule TTP_XOR_QUAD_CurrentVersionRun_af66 {
  strings:
    $key_af66 = { fc 09 [2] d8 07 [2] f3 2b [2] dd 09 [2] c9 12 [2] c6 08 [2] d8 15 [2] da 14 [2] c1 12 [2] dd 15 [2] c1 3a }

  condition:
    any of them
}