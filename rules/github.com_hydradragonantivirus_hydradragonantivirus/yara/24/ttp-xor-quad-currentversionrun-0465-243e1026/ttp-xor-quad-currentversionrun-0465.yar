rule TTP_XOR_QUAD_CurrentVersionRun_0465 {
  strings:
    $key_0465 = { 57 0a [2] 73 04 [2] 58 28 [2] 76 0a [2] 62 11 [2] 6d 0b [2] 73 16 [2] 71 17 [2] 6a 11 [2] 76 16 [2] 6a 39 }

  condition:
    any of them
}