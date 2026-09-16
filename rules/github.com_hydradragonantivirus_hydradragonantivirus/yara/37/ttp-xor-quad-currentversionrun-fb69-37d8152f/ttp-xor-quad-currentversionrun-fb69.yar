rule TTP_XOR_QUAD_CurrentVersionRun_fb69 {
  strings:
    $key_fb69 = { a8 06 [2] 8c 08 [2] a7 24 [2] 89 06 [2] 9d 1d [2] 92 07 [2] 8c 1a [2] 8e 1b [2] 95 1d [2] 89 1a [2] 95 35 }

  condition:
    any of them
}