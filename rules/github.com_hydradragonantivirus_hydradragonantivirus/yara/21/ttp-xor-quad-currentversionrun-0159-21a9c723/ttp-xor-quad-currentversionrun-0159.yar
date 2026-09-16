rule TTP_XOR_QUAD_CurrentVersionRun_0159 {
  strings:
    $key_0159 = { 52 36 [2] 76 38 [2] 5d 14 [2] 73 36 [2] 67 2d [2] 68 37 [2] 76 2a [2] 74 2b [2] 6f 2d [2] 73 2a [2] 6f 05 }

  condition:
    any of them
}