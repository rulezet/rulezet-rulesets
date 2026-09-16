rule TTP_XOR_QUAD_CurrentVersionRun_7190 {
  strings:
    $key_7190 = { 22 ff [2] 06 f1 [2] 2d dd [2] 03 ff [2] 17 e4 [2] 18 fe [2] 06 e3 [2] 04 e2 [2] 1f e4 [2] 03 e3 [2] 1f cc }

  condition:
    any of them
}