rule TTP_XOR_QUAD_CurrentVersionRun_af2d {
  strings:
    $key_af2d = { fc 42 [2] d8 4c [2] f3 60 [2] dd 42 [2] c9 59 [2] c6 43 [2] d8 5e [2] da 5f [2] c1 59 [2] dd 5e [2] c1 71 }

  condition:
    any of them
}