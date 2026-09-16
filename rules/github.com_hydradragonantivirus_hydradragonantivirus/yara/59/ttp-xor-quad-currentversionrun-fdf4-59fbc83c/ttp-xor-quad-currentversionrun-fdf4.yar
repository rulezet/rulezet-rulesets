rule TTP_XOR_QUAD_CurrentVersionRun_fdf4 {
  strings:
    $key_fdf4 = { ae 9b [2] 8a 95 [2] a1 b9 [2] 8f 9b [2] 9b 80 [2] 94 9a [2] 8a 87 [2] 88 86 [2] 93 80 [2] 8f 87 [2] 93 a8 }

  condition:
    any of them
}