rule TTP_XOR_QUAD_CurrentVersionRun_6290 {
  strings:
    $key_6290 = { 31 ff [2] 15 f1 [2] 3e dd [2] 10 ff [2] 04 e4 [2] 0b fe [2] 15 e3 [2] 17 e2 [2] 0c e4 [2] 10 e3 [2] 0c cc }

  condition:
    any of them
}