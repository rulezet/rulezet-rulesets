rule TTP_XOR_QUAD_CurrentVersionRun_a598 {
  strings:
    $key_a598 = { f6 f7 [2] d2 f9 [2] f9 d5 [2] d7 f7 [2] c3 ec [2] cc f6 [2] d2 eb [2] d0 ea [2] cb ec [2] d7 eb [2] cb c4 }

  condition:
    any of them
}