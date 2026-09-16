rule TTP_XOR_QUAD_CurrentVersionRun_5f25 {
  strings:
    $key_5f25 = { 0c 4a [2] 28 44 [2] 03 68 [2] 2d 4a [2] 39 51 [2] 36 4b [2] 28 56 [2] 2a 57 [2] 31 51 [2] 2d 56 [2] 31 79 }

  condition:
    any of them
}