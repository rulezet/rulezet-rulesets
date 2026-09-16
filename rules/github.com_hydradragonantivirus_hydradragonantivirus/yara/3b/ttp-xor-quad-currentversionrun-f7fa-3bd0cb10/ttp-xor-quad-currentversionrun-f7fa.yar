rule TTP_XOR_QUAD_CurrentVersionRun_f7fa {
  strings:
    $key_f7fa = { a4 95 [2] 80 9b [2] ab b7 [2] 85 95 [2] 91 8e [2] 9e 94 [2] 80 89 [2] 82 88 [2] 99 8e [2] 85 89 [2] 99 a6 }

  condition:
    any of them
}