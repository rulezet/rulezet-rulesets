rule TTP_XOR_QUAD_CurrentVersionRun_afd4 {
  strings:
    $key_afd4 = { fc bb [2] d8 b5 [2] f3 99 [2] dd bb [2] c9 a0 [2] c6 ba [2] d8 a7 [2] da a6 [2] c1 a0 [2] dd a7 [2] c1 88 }

  condition:
    any of them
}