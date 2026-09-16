rule TTP_XOR_QUAD_CurrentVersionRun_5f09 {
  strings:
    $key_5f09 = { 0c 66 [2] 28 68 [2] 03 44 [2] 2d 66 [2] 39 7d [2] 36 67 [2] 28 7a [2] 2a 7b [2] 31 7d [2] 2d 7a [2] 31 55 }

  condition:
    any of them
}