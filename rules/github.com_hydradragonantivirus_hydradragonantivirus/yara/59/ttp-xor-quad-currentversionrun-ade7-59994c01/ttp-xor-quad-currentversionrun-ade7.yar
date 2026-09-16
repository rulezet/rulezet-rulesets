rule TTP_XOR_QUAD_CurrentVersionRun_ade7 {
  strings:
    $key_ade7 = { fe 88 [2] da 86 [2] f1 aa [2] df 88 [2] cb 93 [2] c4 89 [2] da 94 [2] d8 95 [2] c3 93 [2] df 94 [2] c3 bb }

  condition:
    any of them
}