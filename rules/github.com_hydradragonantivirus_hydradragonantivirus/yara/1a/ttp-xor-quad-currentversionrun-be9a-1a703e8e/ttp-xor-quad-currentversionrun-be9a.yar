rule TTP_XOR_QUAD_CurrentVersionRun_be9a {
  strings:
    $key_be9a = { ed f5 [2] c9 fb [2] e2 d7 [2] cc f5 [2] d8 ee [2] d7 f4 [2] c9 e9 [2] cb e8 [2] d0 ee [2] cc e9 [2] d0 c6 }

  condition:
    any of them
}