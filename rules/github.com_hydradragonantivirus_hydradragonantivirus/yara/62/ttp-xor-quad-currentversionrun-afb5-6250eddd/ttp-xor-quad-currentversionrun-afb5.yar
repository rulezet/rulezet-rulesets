rule TTP_XOR_QUAD_CurrentVersionRun_afb5 {
  strings:
    $key_afb5 = { fc da [2] d8 d4 [2] f3 f8 [2] dd da [2] c9 c1 [2] c6 db [2] d8 c6 [2] da c7 [2] c1 c1 [2] dd c6 [2] c1 e9 }

  condition:
    any of them
}