rule TTP_XOR_QUAD_CurrentVersionRun_af65 {
  strings:
    $key_af65 = { fc 0a [2] d8 04 [2] f3 28 [2] dd 0a [2] c9 11 [2] c6 0b [2] d8 16 [2] da 17 [2] c1 11 [2] dd 16 [2] c1 39 }

  condition:
    any of them
}