rule TTP_XOR_QUAD_CurrentVersionRun_4b79 {
  strings:
    $key_4b79 = { 18 16 [2] 3c 18 [2] 17 34 [2] 39 16 [2] 2d 0d [2] 22 17 [2] 3c 0a [2] 3e 0b [2] 25 0d [2] 39 0a [2] 25 25 }

  condition:
    any of them
}