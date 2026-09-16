rule TTP_XOR_QUAD_CurrentVersionRun_5a39 {
  strings:
    $key_5a39 = { 09 56 [2] 2d 58 [2] 06 74 [2] 28 56 [2] 3c 4d [2] 33 57 [2] 2d 4a [2] 2f 4b [2] 34 4d [2] 28 4a [2] 34 65 }

  condition:
    any of them
}