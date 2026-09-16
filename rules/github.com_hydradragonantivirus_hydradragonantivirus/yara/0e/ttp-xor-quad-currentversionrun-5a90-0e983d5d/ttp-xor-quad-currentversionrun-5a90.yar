rule TTP_XOR_QUAD_CurrentVersionRun_5a90 {
  strings:
    $key_5a90 = { 09 ff [2] 2d f1 [2] 06 dd [2] 28 ff [2] 3c e4 [2] 33 fe [2] 2d e3 [2] 2f e2 [2] 34 e4 [2] 28 e3 [2] 34 cc }

  condition:
    any of them
}