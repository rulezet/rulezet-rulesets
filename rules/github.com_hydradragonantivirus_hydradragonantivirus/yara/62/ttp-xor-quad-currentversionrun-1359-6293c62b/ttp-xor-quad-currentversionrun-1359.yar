rule TTP_XOR_QUAD_CurrentVersionRun_1359 {
  strings:
    $key_1359 = { 40 36 [2] 64 38 [2] 4f 14 [2] 61 36 [2] 75 2d [2] 7a 37 [2] 64 2a [2] 66 2b [2] 7d 2d [2] 61 2a [2] 7d 05 }

  condition:
    any of them
}