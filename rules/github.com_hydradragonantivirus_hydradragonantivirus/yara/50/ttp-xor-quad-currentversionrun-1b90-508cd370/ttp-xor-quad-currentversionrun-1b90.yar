rule TTP_XOR_QUAD_CurrentVersionRun_1b90 {
  strings:
    $key_1b90 = { 48 ff [2] 6c f1 [2] 47 dd [2] 69 ff [2] 7d e4 [2] 72 fe [2] 6c e3 [2] 6e e2 [2] 75 e4 [2] 69 e3 [2] 75 cc }

  condition:
    any of them
}