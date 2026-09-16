rule TTP_XOR_QUAD_CurrentVersionRun_d690 {
  strings:
    $key_d690 = { 85 ff [2] a1 f1 [2] 8a dd [2] a4 ff [2] b0 e4 [2] bf fe [2] a1 e3 [2] a3 e2 [2] b8 e4 [2] a4 e3 [2] b8 cc }

  condition:
    any of them
}