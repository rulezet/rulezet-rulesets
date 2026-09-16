rule TTP_XOR_QUAD_CurrentVersionRun_af63 {
  strings:
    $key_af63 = { fc 0c [2] d8 02 [2] f3 2e [2] dd 0c [2] c9 17 [2] c6 0d [2] d8 10 [2] da 11 [2] c1 17 [2] dd 10 [2] c1 3f }

  condition:
    any of them
}