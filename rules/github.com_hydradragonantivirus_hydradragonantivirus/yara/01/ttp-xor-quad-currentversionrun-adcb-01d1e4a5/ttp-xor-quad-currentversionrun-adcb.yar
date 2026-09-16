rule TTP_XOR_QUAD_CurrentVersionRun_adcb {
  strings:
    $key_adcb = { fe a4 [2] da aa [2] f1 86 [2] df a4 [2] cb bf [2] c4 a5 [2] da b8 [2] d8 b9 [2] c3 bf [2] df b8 [2] c3 97 }

  condition:
    any of them
}