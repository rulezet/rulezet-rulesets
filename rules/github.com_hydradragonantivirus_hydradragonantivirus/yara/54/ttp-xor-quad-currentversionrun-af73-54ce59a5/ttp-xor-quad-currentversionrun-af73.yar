rule TTP_XOR_QUAD_CurrentVersionRun_af73 {
  strings:
    $key_af73 = { fc 1c [2] d8 12 [2] f3 3e [2] dd 1c [2] c9 07 [2] c6 1d [2] d8 00 [2] da 01 [2] c1 07 [2] dd 00 [2] c1 2f }

  condition:
    any of them
}