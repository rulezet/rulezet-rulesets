rule TTP_XOR_QUAD_CurrentVersionRun_0b59 {
  strings:
    $key_0b59 = { 58 36 [2] 7c 38 [2] 57 14 [2] 79 36 [2] 6d 2d [2] 62 37 [2] 7c 2a [2] 7e 2b [2] 65 2d [2] 79 2a [2] 65 05 }

  condition:
    any of them
}