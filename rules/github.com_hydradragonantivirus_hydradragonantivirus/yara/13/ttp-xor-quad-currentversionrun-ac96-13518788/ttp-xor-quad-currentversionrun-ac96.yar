rule TTP_XOR_QUAD_CurrentVersionRun_ac96 {
  strings:
    $key_ac96 = { ff f9 [2] db f7 [2] f0 db [2] de f9 [2] ca e2 [2] c5 f8 [2] db e5 [2] d9 e4 [2] c2 e2 [2] de e5 [2] c2 ca }

  condition:
    any of them
}