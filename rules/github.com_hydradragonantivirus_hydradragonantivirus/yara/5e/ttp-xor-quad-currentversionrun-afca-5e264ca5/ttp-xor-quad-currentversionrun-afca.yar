rule TTP_XOR_QUAD_CurrentVersionRun_afca {
  strings:
    $key_afca = { fc a5 [2] d8 ab [2] f3 87 [2] dd a5 [2] c9 be [2] c6 a4 [2] d8 b9 [2] da b8 [2] c1 be [2] dd b9 [2] c1 96 }

  condition:
    any of them
}