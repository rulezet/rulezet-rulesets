rule TTP_XOR_QUAD_CurrentVersionRun_4b39 {
  strings:
    $key_4b39 = { 18 56 [2] 3c 58 [2] 17 74 [2] 39 56 [2] 2d 4d [2] 22 57 [2] 3c 4a [2] 3e 4b [2] 25 4d [2] 39 4a [2] 25 65 }

  condition:
    any of them
}