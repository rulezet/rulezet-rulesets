rule TTP_XOR_QUAD_CurrentVersionRun_ed07 {
  strings:
    $key_ed07 = { be 68 [2] 9a 66 [2] b1 4a [2] 9f 68 [2] 8b 73 [2] 84 69 [2] 9a 74 [2] 98 75 [2] 83 73 [2] 9f 74 [2] 83 5b }

  condition:
    any of them
}