rule TTP_XOR_QUAD_CurrentVersionRun_ad96 {
  strings:
    $key_ad96 = { fe f9 [2] da f7 [2] f1 db [2] df f9 [2] cb e2 [2] c4 f8 [2] da e5 [2] d8 e4 [2] c3 e2 [2] df e5 [2] c3 ca }

  condition:
    any of them
}