rule TTP_XOR_QUAD_CurrentVersionRun_ac94 {
  strings:
    $key_ac94 = { ff fb [2] db f5 [2] f0 d9 [2] de fb [2] ca e0 [2] c5 fa [2] db e7 [2] d9 e6 [2] c2 e0 [2] de e7 [2] c2 c8 }

  condition:
    any of them
}