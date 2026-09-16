rule TTP_XOR_QUAD_CurrentVersionRun_addb {
  strings:
    $key_addb = { fe b4 [2] da ba [2] f1 96 [2] df b4 [2] cb af [2] c4 b5 [2] da a8 [2] d8 a9 [2] c3 af [2] df a8 [2] c3 87 }

  condition:
    any of them
}