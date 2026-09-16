rule TTP_XOR_QUAD_CurrentVersionRun_5f58 {
  strings:
    $key_5f58 = { 0c 37 [2] 28 39 [2] 03 15 [2] 2d 37 [2] 39 2c [2] 36 36 [2] 28 2b [2] 2a 2a [2] 31 2c [2] 2d 2b [2] 31 04 }

  condition:
    any of them
}