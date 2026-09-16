rule TTP_XOR_QUAD_CurrentVersionRun_4a90 {
  strings:
    $key_4a90 = { 19 ff [2] 3d f1 [2] 16 dd [2] 38 ff [2] 2c e4 [2] 23 fe [2] 3d e3 [2] 3f e2 [2] 24 e4 [2] 38 e3 [2] 24 cc }

  condition:
    any of them
}