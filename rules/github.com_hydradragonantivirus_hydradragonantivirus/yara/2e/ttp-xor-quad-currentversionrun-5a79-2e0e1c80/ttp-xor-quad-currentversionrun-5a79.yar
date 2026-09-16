rule TTP_XOR_QUAD_CurrentVersionRun_5a79 {
  strings:
    $key_5a79 = { 09 16 [2] 2d 18 [2] 06 34 [2] 28 16 [2] 3c 0d [2] 33 17 [2] 2d 0a [2] 2f 0b [2] 34 0d [2] 28 0a [2] 34 25 }

  condition:
    any of them
}