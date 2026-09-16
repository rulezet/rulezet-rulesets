rule TTP_XOR_QUAD_CurrentVersionRun_4325 {
  strings:
    $key_4325 = { 10 4a [2] 34 44 [2] 1f 68 [2] 31 4a [2] 25 51 [2] 2a 4b [2] 34 56 [2] 36 57 [2] 2d 51 [2] 31 56 [2] 2d 79 }

  condition:
    any of them
}