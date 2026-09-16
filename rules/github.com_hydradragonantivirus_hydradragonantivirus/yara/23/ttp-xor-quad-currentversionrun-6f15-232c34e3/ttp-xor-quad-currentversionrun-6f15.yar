rule TTP_XOR_QUAD_CurrentVersionRun_6f15 {
  strings:
    $key_6f15 = { 3c 7a [2] 18 74 [2] 33 58 [2] 1d 7a [2] 09 61 [2] 06 7b [2] 18 66 [2] 1a 67 [2] 01 61 [2] 1d 66 [2] 01 49 }

  condition:
    any of them
}