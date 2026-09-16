rule TTP_XOR_QUAD_CurrentVersionRun_ad99 {
  strings:
    $key_ad99 = { fe f6 [2] da f8 [2] f1 d4 [2] df f6 [2] cb ed [2] c4 f7 [2] da ea [2] d8 eb [2] c3 ed [2] df ea [2] c3 c5 }

  condition:
    any of them
}