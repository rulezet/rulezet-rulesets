rule TTP_XOR_QUAD_CurrentVersionRun_be86 {
  strings:
    $key_be86 = { ed e9 [2] c9 e7 [2] e2 cb [2] cc e9 [2] d8 f2 [2] d7 e8 [2] c9 f5 [2] cb f4 [2] d0 f2 [2] cc f5 [2] d0 da }

  condition:
    any of them
}