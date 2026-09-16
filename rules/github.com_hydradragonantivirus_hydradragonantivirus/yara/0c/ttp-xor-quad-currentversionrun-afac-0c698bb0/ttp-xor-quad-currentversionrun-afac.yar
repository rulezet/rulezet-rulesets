rule TTP_XOR_QUAD_CurrentVersionRun_afac {
  strings:
    $key_afac = { fc c3 [2] d8 cd [2] f3 e1 [2] dd c3 [2] c9 d8 [2] c6 c2 [2] d8 df [2] da de [2] c1 d8 [2] dd df [2] c1 f0 }

  condition:
    any of them
}