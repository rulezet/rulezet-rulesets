rule TTP_XOR_QUAD_CurrentVersionRun_be93 {
  strings:
    $key_be93 = { ed fc [2] c9 f2 [2] e2 de [2] cc fc [2] d8 e7 [2] d7 fd [2] c9 e0 [2] cb e1 [2] d0 e7 [2] cc e0 [2] d0 cf }

  condition:
    any of them
}