rule TTP_XOR_QUAD_CurrentVersionRun_1f07 {
  strings:
    $key_1f07 = { 4c 68 [2] 68 66 [2] 43 4a [2] 6d 68 [2] 79 73 [2] 76 69 [2] 68 74 [2] 6a 75 [2] 71 73 [2] 6d 74 [2] 71 5b }

  condition:
    any of them
}