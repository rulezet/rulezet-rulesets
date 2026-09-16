rule TTP_XOR_QUAD_CurrentVersionRun_fb35 {
  strings:
    $key_fb35 = { a8 5a [2] 8c 54 [2] a7 78 [2] 89 5a [2] 9d 41 [2] 92 5b [2] 8c 46 [2] 8e 47 [2] 95 41 [2] 89 46 [2] 95 69 }

  condition:
    any of them
}