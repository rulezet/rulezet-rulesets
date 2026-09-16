rule TTP_XOR_QUAD_CurrentVersionRun_af15 {
  strings:
    $key_af15 = { fc 7a [2] d8 74 [2] f3 58 [2] dd 7a [2] c9 61 [2] c6 7b [2] d8 66 [2] da 67 [2] c1 61 [2] dd 66 [2] c1 49 }

  condition:
    any of them
}