rule TTP_XOR_QUAD_CurrentVersionRun_4d58 {
  strings:
    $key_4d58 = { 1e 37 [2] 3a 39 [2] 11 15 [2] 3f 37 [2] 2b 2c [2] 24 36 [2] 3a 2b [2] 38 2a [2] 23 2c [2] 3f 2b [2] 23 04 }

  condition:
    any of them
}