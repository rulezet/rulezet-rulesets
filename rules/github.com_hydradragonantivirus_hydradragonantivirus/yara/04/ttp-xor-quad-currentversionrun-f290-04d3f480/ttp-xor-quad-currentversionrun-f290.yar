rule TTP_XOR_QUAD_CurrentVersionRun_f290 {
  strings:
    $key_f290 = { a1 ff [2] 85 f1 [2] ae dd [2] 80 ff [2] 94 e4 [2] 9b fe [2] 85 e3 [2] 87 e2 [2] 9c e4 [2] 80 e3 [2] 9c cc }

  condition:
    any of them
}