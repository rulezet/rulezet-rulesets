rule TTP_XOR_QUAD_CurrentVersionRun_1f58 {
  strings:
    $key_1f58 = { 4c 37 [2] 68 39 [2] 43 15 [2] 6d 37 [2] 79 2c [2] 76 36 [2] 68 2b [2] 6a 2a [2] 71 2c [2] 6d 2b [2] 71 04 }

  condition:
    any of them
}