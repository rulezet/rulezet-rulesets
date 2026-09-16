rule TTP_XOR_QUAD_CurrentVersionRun_af36 {
  strings:
    $key_af36 = { fc 59 [2] d8 57 [2] f3 7b [2] dd 59 [2] c9 42 [2] c6 58 [2] d8 45 [2] da 44 [2] c1 42 [2] dd 45 [2] c1 6a }

  condition:
    any of them
}