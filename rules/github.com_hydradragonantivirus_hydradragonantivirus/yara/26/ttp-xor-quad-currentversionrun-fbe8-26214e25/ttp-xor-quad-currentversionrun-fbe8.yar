rule TTP_XOR_QUAD_CurrentVersionRun_fbe8 {
  strings:
    $key_fbe8 = { a8 87 [2] 8c 89 [2] a7 a5 [2] 89 87 [2] 9d 9c [2] 92 86 [2] 8c 9b [2] 8e 9a [2] 95 9c [2] 89 9b [2] 95 b4 }

  condition:
    any of them
}