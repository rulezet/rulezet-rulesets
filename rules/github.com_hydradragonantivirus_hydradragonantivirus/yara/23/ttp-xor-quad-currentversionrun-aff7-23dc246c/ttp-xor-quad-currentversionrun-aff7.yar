rule TTP_XOR_QUAD_CurrentVersionRun_aff7 {
  strings:
    $key_aff7 = { fc 98 [2] d8 96 [2] f3 ba [2] dd 98 [2] c9 83 [2] c6 99 [2] d8 84 [2] da 85 [2] c1 83 [2] dd 84 [2] c1 ab }

  condition:
    any of them
}