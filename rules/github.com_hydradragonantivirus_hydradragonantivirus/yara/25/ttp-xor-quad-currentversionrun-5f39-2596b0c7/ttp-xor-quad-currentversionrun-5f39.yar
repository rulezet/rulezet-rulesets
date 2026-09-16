rule TTP_XOR_QUAD_CurrentVersionRun_5f39 {
  strings:
    $key_5f39 = { 0c 56 [2] 28 58 [2] 03 74 [2] 2d 56 [2] 39 4d [2] 36 57 [2] 28 4a [2] 2a 4b [2] 31 4d [2] 2d 4a [2] 31 65 }

  condition:
    any of them
}