rule TTP_XOR_QUAD_CurrentVersionRun_fbe4 {
  strings:
    $key_fbe4 = { a8 8b [2] 8c 85 [2] a7 a9 [2] 89 8b [2] 9d 90 [2] 92 8a [2] 8c 97 [2] 8e 96 [2] 95 90 [2] 89 97 [2] 95 b8 }

  condition:
    any of them
}