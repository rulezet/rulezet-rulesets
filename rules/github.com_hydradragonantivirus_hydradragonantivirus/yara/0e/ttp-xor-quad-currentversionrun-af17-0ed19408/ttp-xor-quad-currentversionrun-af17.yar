rule TTP_XOR_QUAD_CurrentVersionRun_af17 {
  strings:
    $key_af17 = { fc 78 [2] d8 76 [2] f3 5a [2] dd 78 [2] c9 63 [2] c6 79 [2] d8 64 [2] da 65 [2] c1 63 [2] dd 64 [2] c1 4b }

  condition:
    any of them
}