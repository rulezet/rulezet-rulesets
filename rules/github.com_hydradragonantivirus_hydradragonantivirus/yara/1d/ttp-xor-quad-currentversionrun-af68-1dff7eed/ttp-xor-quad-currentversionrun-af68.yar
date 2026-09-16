rule TTP_XOR_QUAD_CurrentVersionRun_af68 {
  strings:
    $key_af68 = { fc 07 [2] d8 09 [2] f3 25 [2] dd 07 [2] c9 1c [2] c6 06 [2] d8 1b [2] da 1a [2] c1 1c [2] dd 1b [2] c1 34 }

  condition:
    any of them
}