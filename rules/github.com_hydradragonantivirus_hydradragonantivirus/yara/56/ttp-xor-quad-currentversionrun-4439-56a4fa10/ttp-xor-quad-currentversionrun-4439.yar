rule TTP_XOR_QUAD_CurrentVersionRun_4439 {
  strings:
    $key_4439 = { 17 56 [2] 33 58 [2] 18 74 [2] 36 56 [2] 22 4d [2] 2d 57 [2] 33 4a [2] 31 4b [2] 2a 4d [2] 36 4a [2] 2a 65 }

  condition:
    any of them
}