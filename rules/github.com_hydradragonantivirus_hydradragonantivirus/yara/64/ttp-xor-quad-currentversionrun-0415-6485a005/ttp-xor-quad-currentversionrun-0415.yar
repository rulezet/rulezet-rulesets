rule TTP_XOR_QUAD_CurrentVersionRun_0415 {
  strings:
    $key_0415 = { 57 7a [2] 73 74 [2] 58 58 [2] 76 7a [2] 62 61 [2] 6d 7b [2] 73 66 [2] 71 67 [2] 6a 61 [2] 76 66 [2] 6a 49 }

  condition:
    any of them
}