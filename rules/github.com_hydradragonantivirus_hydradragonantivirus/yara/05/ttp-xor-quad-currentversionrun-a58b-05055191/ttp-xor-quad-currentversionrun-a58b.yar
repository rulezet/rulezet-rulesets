rule TTP_XOR_QUAD_CurrentVersionRun_a58b {
  strings:
    $key_a58b = { f6 e4 [2] d2 ea [2] f9 c6 [2] d7 e4 [2] c3 ff [2] cc e5 [2] d2 f8 [2] d0 f9 [2] cb ff [2] d7 f8 [2] cb d7 }

  condition:
    any of them
}