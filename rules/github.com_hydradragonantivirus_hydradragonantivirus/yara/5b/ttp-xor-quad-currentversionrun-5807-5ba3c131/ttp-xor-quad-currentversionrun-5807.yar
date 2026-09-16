rule TTP_XOR_QUAD_CurrentVersionRun_5807 {
  strings:
    $key_5807 = { 0b 68 [2] 2f 66 [2] 04 4a [2] 2a 68 [2] 3e 73 [2] 31 69 [2] 2f 74 [2] 2d 75 [2] 36 73 [2] 2a 74 [2] 36 5b }

  condition:
    any of them
}