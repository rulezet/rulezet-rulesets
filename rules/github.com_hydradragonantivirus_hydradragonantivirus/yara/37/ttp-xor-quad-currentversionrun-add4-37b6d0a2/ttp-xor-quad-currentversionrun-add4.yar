rule TTP_XOR_QUAD_CurrentVersionRun_add4 {
  strings:
    $key_add4 = { fe bb [2] da b5 [2] f1 99 [2] df bb [2] cb a0 [2] c4 ba [2] da a7 [2] d8 a6 [2] c3 a0 [2] df a7 [2] c3 88 }

  condition:
    any of them
}