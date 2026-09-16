rule TTP_XOR_QUAD_CurrentVersionRun_f764 {
  strings:
    $key_f764 = { a4 0b [2] 80 05 [2] ab 29 [2] 85 0b [2] 91 10 [2] 9e 0a [2] 80 17 [2] 82 16 [2] 99 10 [2] 85 17 [2] 99 38 }

  condition:
    any of them
}