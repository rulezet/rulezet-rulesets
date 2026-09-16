rule TTP_XOR_QUAD_CurrentVersionRun_f7c7 {
  strings:
    $key_f7c7 = { a4 a8 [2] 80 a6 [2] ab 8a [2] 85 a8 [2] 91 b3 [2] 9e a9 [2] 80 b4 [2] 82 b5 [2] 99 b3 [2] 85 b4 [2] 99 9b }

  condition:
    any of them
}