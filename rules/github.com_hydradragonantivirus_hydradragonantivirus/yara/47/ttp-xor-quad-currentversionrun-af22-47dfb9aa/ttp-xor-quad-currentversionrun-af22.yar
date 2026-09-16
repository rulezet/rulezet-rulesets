rule TTP_XOR_QUAD_CurrentVersionRun_af22 {
  strings:
    $key_af22 = { fc 4d [2] d8 43 [2] f3 6f [2] dd 4d [2] c9 56 [2] c6 4c [2] d8 51 [2] da 50 [2] c1 56 [2] dd 51 [2] c1 7e }

  condition:
    any of them
}