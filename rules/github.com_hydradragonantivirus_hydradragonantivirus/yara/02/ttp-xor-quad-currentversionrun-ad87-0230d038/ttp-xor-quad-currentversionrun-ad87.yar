rule TTP_XOR_QUAD_CurrentVersionRun_ad87 {
  strings:
    $key_ad87 = { fe e8 [2] da e6 [2] f1 ca [2] df e8 [2] cb f3 [2] c4 e9 [2] da f4 [2] d8 f5 [2] c3 f3 [2] df f4 [2] c3 db }

  condition:
    any of them
}