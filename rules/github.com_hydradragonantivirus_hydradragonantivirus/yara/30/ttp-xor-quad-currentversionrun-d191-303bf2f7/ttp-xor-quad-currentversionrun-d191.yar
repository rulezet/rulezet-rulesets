rule TTP_XOR_QUAD_CurrentVersionRun_d191 {
  strings:
    $key_d191 = { 82 fe [2] a6 f0 [2] 8d dc [2] a3 fe [2] b7 e5 [2] b8 ff [2] a6 e2 [2] a4 e3 [2] bf e5 [2] a3 e2 [2] bf cd }

  condition:
    any of them
}