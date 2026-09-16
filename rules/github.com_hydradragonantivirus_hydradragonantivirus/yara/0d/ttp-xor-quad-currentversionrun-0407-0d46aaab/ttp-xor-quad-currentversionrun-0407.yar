rule TTP_XOR_QUAD_CurrentVersionRun_0407 {
  strings:
    $key_0407 = { 57 68 [2] 73 66 [2] 58 4a [2] 76 68 [2] 62 73 [2] 6d 69 [2] 73 74 [2] 71 75 [2] 6a 73 [2] 76 74 [2] 6a 5b }

  condition:
    any of them
}