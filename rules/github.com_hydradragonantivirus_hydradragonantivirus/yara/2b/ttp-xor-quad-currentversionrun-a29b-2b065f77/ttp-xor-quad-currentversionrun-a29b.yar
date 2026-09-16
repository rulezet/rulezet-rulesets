rule TTP_XOR_QUAD_CurrentVersionRun_a29b {
  strings:
    $key_a29b = { f1 f4 [2] d5 fa [2] fe d6 [2] d0 f4 [2] c4 ef [2] cb f5 [2] d5 e8 [2] d7 e9 [2] cc ef [2] d0 e8 [2] cc c7 }

  condition:
    any of them
}