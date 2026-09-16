rule TTP_XOR_QUAD_CurrentVersionRun_ad93 {
  strings:
    $key_ad93 = { fe fc [2] da f2 [2] f1 de [2] df fc [2] cb e7 [2] c4 fd [2] da e0 [2] d8 e1 [2] c3 e7 [2] df e0 [2] c3 cf }

  condition:
    any of them
}