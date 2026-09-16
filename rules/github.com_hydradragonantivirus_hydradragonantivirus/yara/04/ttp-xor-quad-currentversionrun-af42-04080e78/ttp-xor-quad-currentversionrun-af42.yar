rule TTP_XOR_QUAD_CurrentVersionRun_af42 {
  strings:
    $key_af42 = { fc 2d [2] d8 23 [2] f3 0f [2] dd 2d [2] c9 36 [2] c6 2c [2] d8 31 [2] da 30 [2] c1 36 [2] dd 31 [2] c1 1e }

  condition:
    any of them
}