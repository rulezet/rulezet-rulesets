rule TTP_XOR_QUAD_CurrentVersionRun_fb6e {
  strings:
    $key_fb6e = { a8 01 [2] 8c 0f [2] a7 23 [2] 89 01 [2] 9d 1a [2] 92 00 [2] 8c 1d [2] 8e 1c [2] 95 1a [2] 89 1d [2] 95 32 }

  condition:
    any of them
}