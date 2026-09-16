rule TTP_XOR_QUAD_CurrentVersionRun_fb58 {
  strings:
    $key_fb58 = { a8 37 [2] 8c 39 [2] a7 15 [2] 89 37 [2] 9d 2c [2] 92 36 [2] 8c 2b [2] 8e 2a [2] 95 2c [2] 89 2b [2] 95 04 }

  condition:
    any of them
}