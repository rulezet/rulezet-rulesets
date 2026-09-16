rule TTP_XOR_QUAD_CurrentVersionRun_0445 {
  strings:
    $key_0445 = { 57 2a [2] 73 24 [2] 58 08 [2] 76 2a [2] 62 31 [2] 6d 2b [2] 73 36 [2] 71 37 [2] 6a 31 [2] 76 36 [2] 6a 19 }

  condition:
    any of them
}