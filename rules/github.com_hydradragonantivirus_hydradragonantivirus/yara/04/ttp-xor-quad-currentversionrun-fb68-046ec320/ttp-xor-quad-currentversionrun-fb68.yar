rule TTP_XOR_QUAD_CurrentVersionRun_fb68 {
  strings:
    $key_fb68 = { a8 07 [2] 8c 09 [2] a7 25 [2] 89 07 [2] 9d 1c [2] 92 06 [2] 8c 1b [2] 8e 1a [2] 95 1c [2] 89 1b [2] 95 34 }

  condition:
    any of them
}