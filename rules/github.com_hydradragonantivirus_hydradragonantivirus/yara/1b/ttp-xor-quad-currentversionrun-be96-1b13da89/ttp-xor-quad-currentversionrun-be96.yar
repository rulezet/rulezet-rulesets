rule TTP_XOR_QUAD_CurrentVersionRun_be96 {
  strings:
    $key_be96 = { ed f9 [2] c9 f7 [2] e2 db [2] cc f9 [2] d8 e2 [2] d7 f8 [2] c9 e5 [2] cb e4 [2] d0 e2 [2] cc e5 [2] d0 ca }

  condition:
    any of them
}