rule TTP_XOR_QUAD_CurrentVersionRun_7290 {
  strings:
    $key_7290 = { 21 ff [2] 05 f1 [2] 2e dd [2] 00 ff [2] 14 e4 [2] 1b fe [2] 05 e3 [2] 07 e2 [2] 1c e4 [2] 00 e3 [2] 1c cc }

  condition:
    any of them
}