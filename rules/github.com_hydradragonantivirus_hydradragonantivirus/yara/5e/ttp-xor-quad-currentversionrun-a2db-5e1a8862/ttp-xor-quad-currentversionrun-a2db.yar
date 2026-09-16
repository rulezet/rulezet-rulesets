rule TTP_XOR_QUAD_CurrentVersionRun_a2db {
  strings:
    $key_a2db = { f1 b4 [2] d5 ba [2] fe 96 [2] d0 b4 [2] c4 af [2] cb b5 [2] d5 a8 [2] d7 a9 [2] cc af [2] d0 a8 [2] cc 87 }

  condition:
    any of them
}