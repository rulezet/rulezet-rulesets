rule TTP_XOR_QUAD_CurrentVersionRun_a28b {
  strings:
    $key_a28b = { f1 e4 [2] d5 ea [2] fe c6 [2] d0 e4 [2] c4 ff [2] cb e5 [2] d5 f8 [2] d7 f9 [2] cc ff [2] d0 f8 [2] cc d7 }

  condition:
    any of them
}