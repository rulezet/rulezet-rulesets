rule TTP_XOR_QUAD_CurrentVersionRun_f7e8 {
  strings:
    $key_f7e8 = { a4 87 [2] 80 89 [2] ab a5 [2] 85 87 [2] 91 9c [2] 9e 86 [2] 80 9b [2] 82 9a [2] 99 9c [2] 85 9b [2] 99 b4 }

  condition:
    any of them
}