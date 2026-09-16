rule TTP_XOR_QUAD_CurrentVersionRun_2f07 {
  strings:
    $key_2f07 = { 7c 68 [2] 58 66 [2] 73 4a [2] 5d 68 [2] 49 73 [2] 46 69 [2] 58 74 [2] 5a 75 [2] 41 73 [2] 5d 74 [2] 41 5b }

  condition:
    any of them
}