rule TTP_XOR_QUAD_CurrentVersionRun_5ee8 {
  strings:
    $key_5ee8 = { 0d 87 [2] 29 89 [2] 02 a5 [2] 2c 87 [2] 38 9c [2] 37 86 [2] 29 9b [2] 2b 9a [2] 30 9c [2] 2c 9b [2] 30 b4 }

  condition:
    any of them
}