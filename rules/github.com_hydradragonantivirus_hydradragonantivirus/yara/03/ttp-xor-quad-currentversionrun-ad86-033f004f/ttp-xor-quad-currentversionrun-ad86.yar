rule TTP_XOR_QUAD_CurrentVersionRun_ad86 {
  strings:
    $key_ad86 = { fe e9 [2] da e7 [2] f1 cb [2] df e9 [2] cb f2 [2] c4 e8 [2] da f5 [2] d8 f4 [2] c3 f2 [2] df f5 [2] c3 da }

  condition:
    any of them
}