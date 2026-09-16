rule TTP_XOR_QUAD_CurrentVersionRun_af24 {
  strings:
    $key_af24 = { fc 4b [2] d8 45 [2] f3 69 [2] dd 4b [2] c9 50 [2] c6 4a [2] d8 57 [2] da 56 [2] c1 50 [2] dd 57 [2] c1 78 }

  condition:
    any of them
}