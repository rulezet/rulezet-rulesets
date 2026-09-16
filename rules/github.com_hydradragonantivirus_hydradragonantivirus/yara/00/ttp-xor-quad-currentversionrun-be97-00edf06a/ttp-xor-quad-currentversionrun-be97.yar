rule TTP_XOR_QUAD_CurrentVersionRun_be97 {
  strings:
    $key_be97 = { ed f8 [2] c9 f6 [2] e2 da [2] cc f8 [2] d8 e3 [2] d7 f9 [2] c9 e4 [2] cb e5 [2] d0 e3 [2] cc e4 [2] d0 cb }

  condition:
    any of them
}