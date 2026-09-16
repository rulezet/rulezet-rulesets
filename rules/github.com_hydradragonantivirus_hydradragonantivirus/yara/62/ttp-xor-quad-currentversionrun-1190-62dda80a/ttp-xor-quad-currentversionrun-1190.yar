rule TTP_XOR_QUAD_CurrentVersionRun_1190 {
  strings:
    $key_1190 = { 42 ff [2] 66 f1 [2] 4d dd [2] 63 ff [2] 77 e4 [2] 78 fe [2] 66 e3 [2] 64 e2 [2] 7f e4 [2] 63 e3 [2] 7f cc }

  condition:
    any of them
}