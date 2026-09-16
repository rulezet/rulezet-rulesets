rule TTP_XOR_QUAD_CurrentVersionRun_5290 {
  strings:
    $key_5290 = { 01 ff [2] 25 f1 [2] 0e dd [2] 20 ff [2] 34 e4 [2] 3b fe [2] 25 e3 [2] 27 e2 [2] 3c e4 [2] 20 e3 [2] 3c cc }

  condition:
    any of them
}