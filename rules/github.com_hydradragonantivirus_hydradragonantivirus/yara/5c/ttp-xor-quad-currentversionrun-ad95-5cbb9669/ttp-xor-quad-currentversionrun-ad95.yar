rule TTP_XOR_QUAD_CurrentVersionRun_ad95 {
  strings:
    $key_ad95 = { fe fa [2] da f4 [2] f1 d8 [2] df fa [2] cb e1 [2] c4 fb [2] da e6 [2] d8 e7 [2] c3 e1 [2] df e6 [2] c3 c9 }

  condition:
    any of them
}