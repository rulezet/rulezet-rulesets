rule TTP_XOR_QUAD_CurrentVersionRun_0190 {
  strings:
    $key_0190 = { 52 ff [2] 76 f1 [2] 5d dd [2] 73 ff [2] 67 e4 [2] 68 fe [2] 76 e3 [2] 74 e2 [2] 6f e4 [2] 73 e3 [2] 6f cc }

  condition:
    any of them
}