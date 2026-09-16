rule TTP_XOR_QUAD_CurrentVersionRun_a2ca {
  strings:
    $key_a2ca = { f1 a5 [2] d5 ab [2] fe 87 [2] d0 a5 [2] c4 be [2] cb a4 [2] d5 b9 [2] d7 b8 [2] cc be [2] d0 b9 [2] cc 96 }

  condition:
    any of them
}