rule TTP_XOR_QUAD_CurrentVersionRun_adc8 {
  strings:
    $key_adc8 = { fe a7 [2] da a9 [2] f1 85 [2] df a7 [2] cb bc [2] c4 a6 [2] da bb [2] d8 ba [2] c3 bc [2] df bb [2] c3 94 }

  condition:
    any of them
}