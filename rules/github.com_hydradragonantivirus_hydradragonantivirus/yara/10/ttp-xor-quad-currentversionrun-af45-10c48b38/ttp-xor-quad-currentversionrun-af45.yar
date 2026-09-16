rule TTP_XOR_QUAD_CurrentVersionRun_af45 {
  strings:
    $key_af45 = { fc 2a [2] d8 24 [2] f3 08 [2] dd 2a [2] c9 31 [2] c6 2b [2] d8 36 [2] da 37 [2] c1 31 [2] dd 36 [2] c1 19 }

  condition:
    any of them
}