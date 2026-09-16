rule TTP_XOR_QUAD_CurrentVersionRun_f7b3 {
  strings:
    $key_f7b3 = { a4 dc [2] 80 d2 [2] ab fe [2] 85 dc [2] 91 c7 [2] 9e dd [2] 80 c0 [2] 82 c1 [2] 99 c7 [2] 85 c0 [2] 99 ef }

  condition:
    any of them
}