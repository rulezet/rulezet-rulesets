rule TTP_XOR_QUAD_CurrentVersionRun_be85 {
  strings:
    $key_be85 = { ed ea [2] c9 e4 [2] e2 c8 [2] cc ea [2] d8 f1 [2] d7 eb [2] c9 f6 [2] cb f7 [2] d0 f1 [2] cc f6 [2] d0 d9 }

  condition:
    any of them
}