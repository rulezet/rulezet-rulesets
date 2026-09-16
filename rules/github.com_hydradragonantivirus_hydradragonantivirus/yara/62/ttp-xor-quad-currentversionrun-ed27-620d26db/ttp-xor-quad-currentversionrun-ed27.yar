rule TTP_XOR_QUAD_CurrentVersionRun_ed27 {
  strings:
    $key_ed27 = { be 48 [2] 9a 46 [2] b1 6a [2] 9f 48 [2] 8b 53 [2] 84 49 [2] 9a 54 [2] 98 55 [2] 83 53 [2] 9f 54 [2] 83 7b }

  condition:
    any of them
}