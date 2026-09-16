rule TTP_XOR_QUAD_CurrentVersionRun_fb90 {
  strings:
    $key_fb90 = { a8 ff [2] 8c f1 [2] a7 dd [2] 89 ff [2] 9d e4 [2] 92 fe [2] 8c e3 [2] 8e e2 [2] 95 e4 [2] 89 e3 [2] 95 cc }

  condition:
    any of them
}