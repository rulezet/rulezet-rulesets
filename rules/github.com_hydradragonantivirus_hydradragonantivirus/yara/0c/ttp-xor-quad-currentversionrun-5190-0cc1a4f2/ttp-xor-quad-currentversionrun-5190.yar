rule TTP_XOR_QUAD_CurrentVersionRun_5190 {
  strings:
    $key_5190 = { 02 ff [2] 26 f1 [2] 0d dd [2] 23 ff [2] 37 e4 [2] 38 fe [2] 26 e3 [2] 24 e2 [2] 3f e4 [2] 23 e3 [2] 3f cc }

  condition:
    any of them
}