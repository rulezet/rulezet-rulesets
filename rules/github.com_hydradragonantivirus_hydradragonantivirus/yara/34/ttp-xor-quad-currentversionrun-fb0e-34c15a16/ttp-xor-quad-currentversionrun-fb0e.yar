rule TTP_XOR_QUAD_CurrentVersionRun_fb0e {
  strings:
    $key_fb0e = { a8 61 [2] 8c 6f [2] a7 43 [2] 89 61 [2] 9d 7a [2] 92 60 [2] 8c 7d [2] 8e 7c [2] 95 7a [2] 89 7d [2] 95 52 }

  condition:
    any of them
}