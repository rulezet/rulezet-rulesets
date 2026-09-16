rule TTP_XOR_QUAD_CurrentVersionRun_f796 {
  strings:
    $key_f796 = { a4 f9 [2] 80 f7 [2] ab db [2] 85 f9 [2] 91 e2 [2] 9e f8 [2] 80 e5 [2] 82 e4 [2] 99 e2 [2] 85 e5 [2] 99 ca }

  condition:
    any of them
}