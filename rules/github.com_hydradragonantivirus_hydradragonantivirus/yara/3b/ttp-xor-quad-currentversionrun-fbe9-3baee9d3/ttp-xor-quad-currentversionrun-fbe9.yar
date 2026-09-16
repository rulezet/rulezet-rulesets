rule TTP_XOR_QUAD_CurrentVersionRun_fbe9 {
  strings:
    $key_fbe9 = { a8 86 [2] 8c 88 [2] a7 a4 [2] 89 86 [2] 9d 9d [2] 92 87 [2] 8c 9a [2] 8e 9b [2] 95 9d [2] 89 9a [2] 95 b5 }

  condition:
    any of them
}