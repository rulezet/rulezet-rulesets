rule TTP_XOR_QUAD_CurrentVersionRun_a29a {
  strings:
    $key_a29a = { f1 f5 [2] d5 fb [2] fe d7 [2] d0 f5 [2] c4 ee [2] cb f4 [2] d5 e9 [2] d7 e8 [2] cc ee [2] d0 e9 [2] cc c6 }

  condition:
    any of them
}