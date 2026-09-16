rule TTP_XOR_QUAD_CurrentVersionRun_be8a {
  strings:
    $key_be8a = { ed e5 [2] c9 eb [2] e2 c7 [2] cc e5 [2] d8 fe [2] d7 e4 [2] c9 f9 [2] cb f8 [2] d0 fe [2] cc f9 [2] d0 d6 }

  condition:
    any of them
}