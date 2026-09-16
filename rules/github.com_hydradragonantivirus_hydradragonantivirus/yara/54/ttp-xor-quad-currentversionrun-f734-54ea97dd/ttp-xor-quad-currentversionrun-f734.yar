rule TTP_XOR_QUAD_CurrentVersionRun_f734 {
  strings:
    $key_f734 = { a4 5b [2] 80 55 [2] ab 79 [2] 85 5b [2] 91 40 [2] 9e 5a [2] 80 47 [2] 82 46 [2] 99 40 [2] 85 47 [2] 99 68 }

  condition:
    any of them
}