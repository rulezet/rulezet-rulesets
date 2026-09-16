rule TTP_XOR_QUAD_CurrentVersionRun_fdf8 {
  strings:
    $key_fdf8 = { ae 97 [2] 8a 99 [2] a1 b5 [2] 8f 97 [2] 9b 8c [2] 94 96 [2] 8a 8b [2] 88 8a [2] 93 8c [2] 8f 8b [2] 93 a4 }

  condition:
    any of them
}