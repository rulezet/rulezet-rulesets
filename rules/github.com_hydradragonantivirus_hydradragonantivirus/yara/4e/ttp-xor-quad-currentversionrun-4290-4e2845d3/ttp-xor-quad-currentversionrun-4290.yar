rule TTP_XOR_QUAD_CurrentVersionRun_4290 {
  strings:
    $key_4290 = { 11 ff [2] 35 f1 [2] 1e dd [2] 30 ff [2] 24 e4 [2] 2b fe [2] 35 e3 [2] 37 e2 [2] 2c e4 [2] 30 e3 [2] 2c cc }

  condition:
    any of them
}