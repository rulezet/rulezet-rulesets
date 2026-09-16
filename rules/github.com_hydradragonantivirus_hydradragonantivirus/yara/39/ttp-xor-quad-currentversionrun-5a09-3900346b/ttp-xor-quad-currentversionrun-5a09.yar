rule TTP_XOR_QUAD_CurrentVersionRun_5a09 {
  strings:
    $key_5a09 = { 09 66 [2] 2d 68 [2] 06 44 [2] 28 66 [2] 3c 7d [2] 33 67 [2] 2d 7a [2] 2f 7b [2] 34 7d [2] 28 7a [2] 34 55 }

  condition:
    any of them
}