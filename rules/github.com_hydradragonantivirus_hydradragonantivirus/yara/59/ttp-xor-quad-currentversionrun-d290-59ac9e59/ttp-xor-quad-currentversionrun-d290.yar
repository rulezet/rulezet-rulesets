rule TTP_XOR_QUAD_CurrentVersionRun_d290 {
  strings:
    $key_d290 = { 81 ff [2] a5 f1 [2] 8e dd [2] a0 ff [2] b4 e4 [2] bb fe [2] a5 e3 [2] a7 e2 [2] bc e4 [2] a0 e3 [2] bc cc }

  condition:
    any of them
}