rule TTP_XOR_QUAD_CurrentVersionRun_af67 {
  strings:
    $key_af67 = { fc 08 [2] d8 06 [2] f3 2a [2] dd 08 [2] c9 13 [2] c6 09 [2] d8 14 [2] da 15 [2] c1 13 [2] dd 14 [2] c1 3b }

  condition:
    any of them
}