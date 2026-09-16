rule TTP_XOR_QUAD_CurrentVersionRun_ed57 {
  strings:
    $key_ed57 = { be 38 [2] 9a 36 [2] b1 1a [2] 9f 38 [2] 8b 23 [2] 84 39 [2] 9a 24 [2] 98 25 [2] 83 23 [2] 9f 24 [2] 83 0b }

  condition:
    any of them
}