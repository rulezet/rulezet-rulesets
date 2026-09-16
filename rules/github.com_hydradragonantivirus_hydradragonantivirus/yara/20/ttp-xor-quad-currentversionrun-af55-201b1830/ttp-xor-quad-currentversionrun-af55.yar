rule TTP_XOR_QUAD_CurrentVersionRun_af55 {
  strings:
    $key_af55 = { fc 3a [2] d8 34 [2] f3 18 [2] dd 3a [2] c9 21 [2] c6 3b [2] d8 26 [2] da 27 [2] c1 21 [2] dd 26 [2] c1 09 }

  condition:
    any of them
}