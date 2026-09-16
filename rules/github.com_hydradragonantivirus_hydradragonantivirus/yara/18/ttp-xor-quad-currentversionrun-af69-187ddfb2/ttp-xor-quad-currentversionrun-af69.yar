rule TTP_XOR_QUAD_CurrentVersionRun_af69 {
  strings:
    $key_af69 = { fc 06 [2] d8 08 [2] f3 24 [2] dd 06 [2] c9 1d [2] c6 07 [2] d8 1a [2] da 1b [2] c1 1d [2] dd 1a [2] c1 35 }

  condition:
    any of them
}