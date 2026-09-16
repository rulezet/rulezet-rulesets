rule TTP_XOR_QUAD_CurrentVersionRun_af2c {
  strings:
    $key_af2c = { fc 43 [2] d8 4d [2] f3 61 [2] dd 43 [2] c9 58 [2] c6 42 [2] d8 5f [2] da 5e [2] c1 58 [2] dd 5f [2] c1 70 }

  condition:
    any of them
}