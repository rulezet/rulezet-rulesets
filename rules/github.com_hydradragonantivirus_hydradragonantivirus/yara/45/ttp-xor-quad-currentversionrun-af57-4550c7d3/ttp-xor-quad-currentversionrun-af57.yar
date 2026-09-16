rule TTP_XOR_QUAD_CurrentVersionRun_af57 {
  strings:
    $key_af57 = { fc 38 [2] d8 36 [2] f3 1a [2] dd 38 [2] c9 23 [2] c6 39 [2] d8 24 [2] da 25 [2] c1 23 [2] dd 24 [2] c1 0b }

  condition:
    any of them
}