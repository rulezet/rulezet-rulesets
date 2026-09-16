rule TTP_XOR_QUAD_CurrentVersionRun_a28a {
  strings:
    $key_a28a = { f1 e5 [2] d5 eb [2] fe c7 [2] d0 e5 [2] c4 fe [2] cb e4 [2] d5 f9 [2] d7 f8 [2] cc fe [2] d0 f9 [2] cc d6 }

  condition:
    any of them
}