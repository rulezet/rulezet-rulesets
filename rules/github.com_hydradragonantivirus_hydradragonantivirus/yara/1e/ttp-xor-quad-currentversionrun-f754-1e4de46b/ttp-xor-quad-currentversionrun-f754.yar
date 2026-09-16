rule TTP_XOR_QUAD_CurrentVersionRun_f754 {
  strings:
    $key_f754 = { a4 3b [2] 80 35 [2] ab 19 [2] 85 3b [2] 91 20 [2] 9e 3a [2] 80 27 [2] 82 26 [2] 99 20 [2] 85 27 [2] 99 08 }

  condition:
    any of them
}