rule TTP_XOR_QUAD_CurrentVersionRun_f7e4 {
  strings:
    $key_f7e4 = { a4 8b [2] 80 85 [2] ab a9 [2] 85 8b [2] 91 90 [2] 9e 8a [2] 80 97 [2] 82 96 [2] 99 90 [2] 85 97 [2] 99 b8 }

  condition:
    any of them
}