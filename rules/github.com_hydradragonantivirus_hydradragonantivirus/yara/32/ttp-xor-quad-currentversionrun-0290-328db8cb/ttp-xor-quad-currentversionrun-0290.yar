rule TTP_XOR_QUAD_CurrentVersionRun_0290 {
  strings:
    $key_0290 = { 51 ff [2] 75 f1 [2] 5e dd [2] 70 ff [2] 64 e4 [2] 6b fe [2] 75 e3 [2] 77 e2 [2] 6c e4 [2] 70 e3 [2] 6c cc }

  condition:
    any of them
}