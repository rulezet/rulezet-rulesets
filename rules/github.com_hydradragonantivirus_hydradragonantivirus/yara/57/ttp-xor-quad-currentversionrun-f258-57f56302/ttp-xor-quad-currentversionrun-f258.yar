rule TTP_XOR_QUAD_CurrentVersionRun_f258 {
  strings:
    $key_f258 = { a1 37 [2] 85 39 [2] ae 15 [2] 80 37 [2] 94 2c [2] 9b 36 [2] 85 2b [2] 87 2a [2] 9c 2c [2] 80 2b [2] 9c 04 }

  condition:
    any of them
}