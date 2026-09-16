rule TTP_XOR_QUAD_CurrentVersionRun_af44 {
  strings:
    $key_af44 = { fc 2b [2] d8 25 [2] f3 09 [2] dd 2b [2] c9 30 [2] c6 2a [2] d8 37 [2] da 36 [2] c1 30 [2] dd 37 [2] c1 18 }

  condition:
    any of them
}