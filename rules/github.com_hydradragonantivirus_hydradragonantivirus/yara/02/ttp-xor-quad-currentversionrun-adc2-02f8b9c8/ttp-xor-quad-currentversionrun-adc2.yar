rule TTP_XOR_QUAD_CurrentVersionRun_adc2 {
  strings:
    $key_adc2 = { fe ad [2] da a3 [2] f1 8f [2] df ad [2] cb b6 [2] c4 ac [2] da b1 [2] d8 b0 [2] c3 b6 [2] df b1 [2] c3 9e }

  condition:
    any of them
}