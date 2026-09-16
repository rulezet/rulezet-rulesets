rule TTP_XOR_QUAD_CurrentVersionRun_ad89 {
  strings:
    $key_ad89 = { fe e6 [2] da e8 [2] f1 c4 [2] df e6 [2] cb fd [2] c4 e7 [2] da fa [2] d8 fb [2] c3 fd [2] df fa [2] c3 d5 }

  condition:
    any of them
}