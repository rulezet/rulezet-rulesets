rule TTP_XOR_QUAD_CurrentVersionRun_0429 {
  strings:
    $key_0429 = { 57 46 [2] 73 48 [2] 58 64 [2] 76 46 [2] 62 5d [2] 6d 47 [2] 73 5a [2] 71 5b [2] 6a 5d [2] 76 5a [2] 6a 75 }

  condition:
    any of them
}