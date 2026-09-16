rule TTP_XOR_QUAD_CurrentVersionRun_a2dd {
  strings:
    $key_a2dd = { f1 b2 [2] d5 bc [2] fe 90 [2] d0 b2 [2] c4 a9 [2] cb b3 [2] d5 ae [2] d7 af [2] cc a9 [2] d0 ae [2] cc 81 }

  condition:
    any of them
}