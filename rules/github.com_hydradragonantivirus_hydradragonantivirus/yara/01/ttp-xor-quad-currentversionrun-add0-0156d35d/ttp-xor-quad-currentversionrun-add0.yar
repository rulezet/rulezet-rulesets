rule TTP_XOR_QUAD_CurrentVersionRun_add0 {
  strings:
    $key_add0 = { fe bf [2] da b1 [2] f1 9d [2] df bf [2] cb a4 [2] c4 be [2] da a3 [2] d8 a2 [2] c3 a4 [2] df a3 [2] c3 8c }

  condition:
    any of them
}