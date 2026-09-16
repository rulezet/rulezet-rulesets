rule TTP_XOR_QUAD_CurrentVersionRun_5ff9 {
  strings:
    $key_5ff9 = { 0c 96 [2] 28 98 [2] 03 b4 [2] 2d 96 [2] 39 8d [2] 36 97 [2] 28 8a [2] 2a 8b [2] 31 8d [2] 2d 8a [2] 31 a5 }

  condition:
    any of them
}