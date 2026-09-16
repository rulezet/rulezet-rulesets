rule TTP_XOR_QUAD_CurrentVersionRun_fb59 {
  strings:
    $key_fb59 = { a8 36 [2] 8c 38 [2] a7 14 [2] 89 36 [2] 9d 2d [2] 92 37 [2] 8c 2a [2] 8e 2b [2] 95 2d [2] 89 2a [2] 95 05 }

  condition:
    any of them
}