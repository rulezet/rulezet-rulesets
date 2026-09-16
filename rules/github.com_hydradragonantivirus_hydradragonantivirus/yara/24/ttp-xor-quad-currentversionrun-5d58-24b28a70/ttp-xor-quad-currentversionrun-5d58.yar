rule TTP_XOR_QUAD_CurrentVersionRun_5d58 {
  strings:
    $key_5d58 = { 0e 37 [2] 2a 39 [2] 01 15 [2] 2f 37 [2] 3b 2c [2] 34 36 [2] 2a 2b [2] 28 2a [2] 33 2c [2] 2f 2b [2] 33 04 }

  condition:
    any of them
}