rule TTP_XOR_QUAD_CurrentVersionRun_ea57 {
  strings:
    $key_ea57 = { b9 38 [2] 9d 36 [2] b6 1a [2] 98 38 [2] 8c 23 [2] 83 39 [2] 9d 24 [2] 9f 25 [2] 84 23 [2] 98 24 [2] 84 0b }

  condition:
    any of them
}