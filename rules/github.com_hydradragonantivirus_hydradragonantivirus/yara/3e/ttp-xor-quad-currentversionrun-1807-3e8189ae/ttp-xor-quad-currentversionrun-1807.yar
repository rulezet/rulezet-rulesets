rule TTP_XOR_QUAD_CurrentVersionRun_1807 {
  strings:
    $key_1807 = { 4b 68 [2] 6f 66 [2] 44 4a [2] 6a 68 [2] 7e 73 [2] 71 69 [2] 6f 74 [2] 6d 75 [2] 76 73 [2] 6a 74 [2] 76 5b }

  condition:
    any of them
}