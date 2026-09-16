rule TTP_XOR_QUAD_CurrentVersionRun_afb9 {
  strings:
    $key_afb9 = { fc d6 [2] d8 d8 [2] f3 f4 [2] dd d6 [2] c9 cd [2] c6 d7 [2] d8 ca [2] da cb [2] c1 cd [2] dd ca [2] c1 e5 }

  condition:
    any of them
}