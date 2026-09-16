rule TTP_XOR_QUAD_CurrentVersionRun_af60 {
  strings:
    $key_af60 = { fc 0f [2] d8 01 [2] f3 2d [2] dd 0f [2] c9 14 [2] c6 0e [2] d8 13 [2] da 12 [2] c1 14 [2] dd 13 [2] c1 3c }

  condition:
    any of them
}