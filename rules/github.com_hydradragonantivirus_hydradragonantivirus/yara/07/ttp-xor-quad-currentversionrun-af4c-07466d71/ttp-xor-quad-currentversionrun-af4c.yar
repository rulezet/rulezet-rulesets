rule TTP_XOR_QUAD_CurrentVersionRun_af4c {
  strings:
    $key_af4c = { fc 23 [2] d8 2d [2] f3 01 [2] dd 23 [2] c9 38 [2] c6 22 [2] d8 3f [2] da 3e [2] c1 38 [2] dd 3f [2] c1 10 }

  condition:
    any of them
}