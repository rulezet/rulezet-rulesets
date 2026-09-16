rule TTP_XOR_QUAD_CurrentVersionRun_0b90 {
  strings:
    $key_0b90 = { 58 ff [2] 7c f1 [2] 57 dd [2] 79 ff [2] 6d e4 [2] 62 fe [2] 7c e3 [2] 7e e2 [2] 65 e4 [2] 79 e3 [2] 65 cc }

  condition:
    any of them
}