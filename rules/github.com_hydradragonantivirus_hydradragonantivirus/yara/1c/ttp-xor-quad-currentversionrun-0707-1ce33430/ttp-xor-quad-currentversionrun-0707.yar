rule TTP_XOR_QUAD_CurrentVersionRun_0707 {
  strings:
    $key_0707 = { 54 68 [2] 70 66 [2] 5b 4a [2] 75 68 [2] 61 73 [2] 6e 69 [2] 70 74 [2] 72 75 [2] 69 73 [2] 75 74 [2] 69 5b }

  condition:
    any of them
}