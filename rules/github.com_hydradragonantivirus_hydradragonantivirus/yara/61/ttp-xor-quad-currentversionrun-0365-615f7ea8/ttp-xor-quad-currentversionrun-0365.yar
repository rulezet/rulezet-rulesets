rule TTP_XOR_QUAD_CurrentVersionRun_0365 {
  strings:
    $key_0365 = { 50 0a [2] 74 04 [2] 5f 28 [2] 71 0a [2] 65 11 [2] 6a 0b [2] 74 16 [2] 76 17 [2] 6d 11 [2] 71 16 [2] 6d 39 }

  condition:
    any of them
}