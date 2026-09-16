rule TTP_XOR_QUAD_CurrentVersionRun_4807 {
  strings:
    $key_4807 = { 1b 68 [2] 3f 66 [2] 14 4a [2] 3a 68 [2] 2e 73 [2] 21 69 [2] 3f 74 [2] 3d 75 [2] 26 73 [2] 3a 74 [2] 26 5b }

  condition:
    any of them
}