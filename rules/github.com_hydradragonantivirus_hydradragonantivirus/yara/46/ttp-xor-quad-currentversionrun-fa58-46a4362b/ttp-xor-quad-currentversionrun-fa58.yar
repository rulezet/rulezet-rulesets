rule TTP_XOR_QUAD_CurrentVersionRun_fa58 {
  strings:
    $key_fa58 = { a9 37 [2] 8d 39 [2] a6 15 [2] 88 37 [2] 9c 2c [2] 93 36 [2] 8d 2b [2] 8f 2a [2] 94 2c [2] 88 2b [2] 94 04 }

  condition:
    any of them
}