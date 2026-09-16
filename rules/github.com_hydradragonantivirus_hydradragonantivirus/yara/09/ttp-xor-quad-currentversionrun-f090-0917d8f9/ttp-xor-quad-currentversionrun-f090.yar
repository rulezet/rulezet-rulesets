rule TTP_XOR_QUAD_CurrentVersionRun_f090 {
  strings:
    $key_f090 = { a3 ff [2] 87 f1 [2] ac dd [2] 82 ff [2] 96 e4 [2] 99 fe [2] 87 e3 [2] 85 e2 [2] 9e e4 [2] 82 e3 [2] 9e cc }

  condition:
    any of them
}