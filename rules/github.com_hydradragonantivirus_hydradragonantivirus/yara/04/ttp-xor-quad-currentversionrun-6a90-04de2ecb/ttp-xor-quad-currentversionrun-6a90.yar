rule TTP_XOR_QUAD_CurrentVersionRun_6a90 {
  strings:
    $key_6a90 = { 39 ff [2] 1d f1 [2] 36 dd [2] 18 ff [2] 0c e4 [2] 03 fe [2] 1d e3 [2] 1f e2 [2] 04 e4 [2] 18 e3 [2] 04 cc }

  condition:
    any of them
}