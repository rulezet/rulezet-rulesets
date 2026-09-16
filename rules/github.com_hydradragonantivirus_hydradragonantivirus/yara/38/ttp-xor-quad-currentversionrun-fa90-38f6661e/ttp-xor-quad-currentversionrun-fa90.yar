rule TTP_XOR_QUAD_CurrentVersionRun_fa90 {
  strings:
    $key_fa90 = { a9 ff [2] 8d f1 [2] a6 dd [2] 88 ff [2] 9c e4 [2] 93 fe [2] 8d e3 [2] 8f e2 [2] 94 e4 [2] 88 e3 [2] 94 cc }

  condition:
    any of them
}