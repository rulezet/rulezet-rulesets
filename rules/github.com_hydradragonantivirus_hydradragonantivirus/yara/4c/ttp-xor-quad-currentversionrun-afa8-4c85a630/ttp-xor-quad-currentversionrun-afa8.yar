rule TTP_XOR_QUAD_CurrentVersionRun_afa8 {
  strings:
    $key_afa8 = { fc c7 [2] d8 c9 [2] f3 e5 [2] dd c7 [2] c9 dc [2] c6 c6 [2] d8 db [2] da da [2] c1 dc [2] dd db [2] c1 f4 }

  condition:
    any of them
}