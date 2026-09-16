rule TTP_XOR_QUAD_CurrentVersionRun_4190 {
  strings:
    $key_4190 = { 12 ff [2] 36 f1 [2] 1d dd [2] 33 ff [2] 27 e4 [2] 28 fe [2] 36 e3 [2] 34 e2 [2] 2f e4 [2] 33 e3 [2] 2f cc }

  condition:
    any of them
}