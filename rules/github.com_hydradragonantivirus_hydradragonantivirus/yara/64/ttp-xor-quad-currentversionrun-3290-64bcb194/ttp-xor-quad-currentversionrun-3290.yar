rule TTP_XOR_QUAD_CurrentVersionRun_3290 {
  strings:
    $key_3290 = { 61 ff [2] 45 f1 [2] 6e dd [2] 40 ff [2] 54 e4 [2] 5b fe [2] 45 e3 [2] 47 e2 [2] 5c e4 [2] 40 e3 [2] 5c cc }

  condition:
    any of them
}