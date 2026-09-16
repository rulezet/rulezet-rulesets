rule TTP_XOR_QUAD_CurrentVersionRun_fb29 {
  strings:
    $key_fb29 = { a8 46 [2] 8c 48 [2] a7 64 [2] 89 46 [2] 9d 5d [2] 92 47 [2] 8c 5a [2] 8e 5b [2] 95 5d [2] 89 5a [2] 95 75 }

  condition:
    any of them
}