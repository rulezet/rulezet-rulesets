rule TTP_XOR_QUAD_CurrentVersionRun_be8b {
  strings:
    $key_be8b = { ed e4 [2] c9 ea [2] e2 c6 [2] cc e4 [2] d8 ff [2] d7 e5 [2] c9 f8 [2] cb f9 [2] d0 ff [2] cc f8 [2] d0 d7 }

  condition:
    any of them
}