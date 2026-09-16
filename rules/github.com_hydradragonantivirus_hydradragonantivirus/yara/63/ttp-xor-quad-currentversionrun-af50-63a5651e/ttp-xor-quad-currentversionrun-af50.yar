rule TTP_XOR_QUAD_CurrentVersionRun_af50 {
  strings:
    $key_af50 = { fc 3f [2] d8 31 [2] f3 1d [2] dd 3f [2] c9 24 [2] c6 3e [2] d8 23 [2] da 22 [2] c1 24 [2] dd 23 [2] c1 0c }

  condition:
    any of them
}