rule TTP_XOR_QUAD_CurrentVersionRun_af39 {
  strings:
    $key_af39 = { fc 56 [2] d8 58 [2] f3 74 [2] dd 56 [2] c9 4d [2] c6 57 [2] d8 4a [2] da 4b [2] c1 4d [2] dd 4a [2] c1 65 }

  condition:
    any of them
}