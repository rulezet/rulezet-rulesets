rule TTP_XOR_QUAD_CurrentVersionRun_a584 {
  strings:
    $key_a584 = { f6 eb [2] d2 e5 [2] f9 c9 [2] d7 eb [2] c3 f0 [2] cc ea [2] d2 f7 [2] d0 f6 [2] cb f0 [2] d7 f7 [2] cb d8 }

  condition:
    any of them
}