rule TTP_XOR_QUAD_CurrentVersionRun_af43 {
  strings:
    $key_af43 = { fc 2c [2] d8 22 [2] f3 0e [2] dd 2c [2] c9 37 [2] c6 2d [2] d8 30 [2] da 31 [2] c1 37 [2] dd 30 [2] c1 1f }

  condition:
    any of them
}