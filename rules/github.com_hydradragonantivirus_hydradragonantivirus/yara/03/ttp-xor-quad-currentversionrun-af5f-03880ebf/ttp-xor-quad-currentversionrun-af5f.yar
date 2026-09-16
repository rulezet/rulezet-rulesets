rule TTP_XOR_QUAD_CurrentVersionRun_af5f {
  strings:
    $key_af5f = { fc 30 [2] d8 3e [2] f3 12 [2] dd 30 [2] c9 2b [2] c6 31 [2] d8 2c [2] da 2d [2] c1 2b [2] dd 2c [2] c1 03 }

  condition:
    any of them
}