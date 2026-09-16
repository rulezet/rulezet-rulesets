rule TTP_XOR_QUAD_CurrentVersionRun_ad84 {
  strings:
    $key_ad84 = { fe eb [2] da e5 [2] f1 c9 [2] df eb [2] cb f0 [2] c4 ea [2] da f7 [2] d8 f6 [2] c3 f0 [2] df f7 [2] c3 d8 }

  condition:
    any of them
}