rule TTP_XOR_QUAD_CurrentVersionRun_5f07 {
  strings:
    $key_5f07 = { 0c 68 [2] 28 66 [2] 03 4a [2] 2d 68 [2] 39 73 [2] 36 69 [2] 28 74 [2] 2a 75 [2] 31 73 [2] 2d 74 [2] 31 5b }

  condition:
    any of them
}