rule TTP_XOR_QUAD_CurrentVersionRun_f390 {
  strings:
    $key_f390 = { a0 ff [2] 84 f1 [2] af dd [2] 81 ff [2] 95 e4 [2] 9a fe [2] 84 e3 [2] 86 e2 [2] 9d e4 [2] 81 e3 [2] 9d cc }

  condition:
    any of them
}