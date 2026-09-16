rule TTP_XOR_QUAD_CurrentVersionRun_be84 {
  strings:
    $key_be84 = { ed eb [2] c9 e5 [2] e2 c9 [2] cc eb [2] d8 f0 [2] d7 ea [2] c9 f7 [2] cb f6 [2] d0 f0 [2] cc f7 [2] d0 d8 }

  condition:
    any of them
}