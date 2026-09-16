rule TTP_XOR_QUAD_CurrentVersionRun_0e58 {
  strings:
    $key_0e58 = { 5d 37 [2] 79 39 [2] 52 15 [2] 7c 37 [2] 68 2c [2] 67 36 [2] 79 2b [2] 7b 2a [2] 60 2c [2] 7c 2b [2] 60 04 }

  condition:
    any of them
}