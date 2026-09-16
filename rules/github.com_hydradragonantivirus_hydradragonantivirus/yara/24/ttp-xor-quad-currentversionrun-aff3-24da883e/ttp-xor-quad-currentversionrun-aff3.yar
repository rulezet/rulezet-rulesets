rule TTP_XOR_QUAD_CurrentVersionRun_aff3 {
  strings:
    $key_aff3 = { fc 9c [2] d8 92 [2] f3 be [2] dd 9c [2] c9 87 [2] c6 9d [2] d8 80 [2] da 81 [2] c1 87 [2] dd 80 [2] c1 af }

  condition:
    any of them
}