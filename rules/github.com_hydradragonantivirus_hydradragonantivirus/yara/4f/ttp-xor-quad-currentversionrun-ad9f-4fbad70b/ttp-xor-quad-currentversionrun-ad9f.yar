rule TTP_XOR_QUAD_CurrentVersionRun_ad9f {
  strings:
    $key_ad9f = { fe f0 [2] da fe [2] f1 d2 [2] df f0 [2] cb eb [2] c4 f1 [2] da ec [2] d8 ed [2] c3 eb [2] df ec [2] c3 c3 }

  condition:
    any of them
}