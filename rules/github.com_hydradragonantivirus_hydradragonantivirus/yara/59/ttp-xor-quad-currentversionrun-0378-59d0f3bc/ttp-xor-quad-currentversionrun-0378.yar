rule TTP_XOR_QUAD_CurrentVersionRun_0378 {
  strings:
    $key_0378 = { 50 17 [2] 74 19 [2] 5f 35 [2] 71 17 [2] 65 0c [2] 6a 16 [2] 74 0b [2] 76 0a [2] 6d 0c [2] 71 0b [2] 6d 24 }

  condition:
    any of them
}