rule TTP_XOR_QUAD_CurrentVersionRun_2d07 {
  strings:
    $key_2d07 = { 7e 68 [2] 5a 66 [2] 71 4a [2] 5f 68 [2] 4b 73 [2] 44 69 [2] 5a 74 [2] 58 75 [2] 43 73 [2] 5f 74 [2] 43 5b }

  condition:
    any of them
}