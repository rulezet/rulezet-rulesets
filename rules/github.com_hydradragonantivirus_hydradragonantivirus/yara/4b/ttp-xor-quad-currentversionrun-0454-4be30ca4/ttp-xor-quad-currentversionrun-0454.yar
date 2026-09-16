rule TTP_XOR_QUAD_CurrentVersionRun_0454 {
  strings:
    $key_0454 = { 57 3b [2] 73 35 [2] 58 19 [2] 76 3b [2] 62 20 [2] 6d 3a [2] 73 27 [2] 71 26 [2] 6a 20 [2] 76 27 [2] 6a 08 }

  condition:
    any of them
}