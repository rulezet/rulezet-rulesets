rule TTP_XOR_QUAD_CurrentVersionRun_af5b {
  strings:
    $key_af5b = { fc 34 [2] d8 3a [2] f3 16 [2] dd 34 [2] c9 2f [2] c6 35 [2] d8 28 [2] da 29 [2] c1 2f [2] dd 28 [2] c1 07 }

  condition:
    any of them
}