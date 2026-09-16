rule TTP_XOR_QUAD_CurrentVersionRun_0359 {
  strings:
    $key_0359 = { 50 36 [2] 74 38 [2] 5f 14 [2] 71 36 [2] 65 2d [2] 6a 37 [2] 74 2a [2] 76 2b [2] 6d 2d [2] 71 2a [2] 6d 05 }

  condition:
    any of them
}