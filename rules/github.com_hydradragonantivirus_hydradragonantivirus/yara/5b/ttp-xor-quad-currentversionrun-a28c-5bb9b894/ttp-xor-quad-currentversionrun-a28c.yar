rule TTP_XOR_QUAD_CurrentVersionRun_a28c {
  strings:
    $key_a28c = { f1 e3 [2] d5 ed [2] fe c1 [2] d0 e3 [2] c4 f8 [2] cb e2 [2] d5 ff [2] d7 fe [2] cc f8 [2] d0 ff [2] cc d0 }

  condition:
    any of them
}