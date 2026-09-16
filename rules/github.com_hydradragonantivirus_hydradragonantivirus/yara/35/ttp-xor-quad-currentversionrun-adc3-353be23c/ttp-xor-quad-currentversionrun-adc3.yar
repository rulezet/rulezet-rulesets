rule TTP_XOR_QUAD_CurrentVersionRun_adc3 {
  strings:
    $key_adc3 = { fe ac [2] da a2 [2] f1 8e [2] df ac [2] cb b7 [2] c4 ad [2] da b0 [2] d8 b1 [2] c3 b7 [2] df b0 [2] c3 9f }

  condition:
    any of them
}