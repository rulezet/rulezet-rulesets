rule TTP_XOR_QUAD_CurrentVersionRun_af64 {
  strings:
    $key_af64 = { fc 0b [2] d8 05 [2] f3 29 [2] dd 0b [2] c9 10 [2] c6 0a [2] d8 17 [2] da 16 [2] c1 10 [2] dd 17 [2] c1 38 }

  condition:
    any of them
}