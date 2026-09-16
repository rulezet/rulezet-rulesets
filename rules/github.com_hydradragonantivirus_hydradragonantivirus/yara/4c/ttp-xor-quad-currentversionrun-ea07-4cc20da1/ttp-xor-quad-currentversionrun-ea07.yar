rule TTP_XOR_QUAD_CurrentVersionRun_ea07 {
  strings:
    $key_ea07 = { b9 68 [2] 9d 66 [2] b6 4a [2] 98 68 [2] 8c 73 [2] 83 69 [2] 9d 74 [2] 9f 75 [2] 84 73 [2] 98 74 [2] 84 5b }

  condition:
    any of them
}