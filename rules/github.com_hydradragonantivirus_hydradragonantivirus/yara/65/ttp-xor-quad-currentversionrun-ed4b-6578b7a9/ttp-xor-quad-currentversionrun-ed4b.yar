rule TTP_XOR_QUAD_CurrentVersionRun_ed4b {
  strings:
    $key_ed4b = { be 24 [2] 9a 2a [2] b1 06 [2] 9f 24 [2] 8b 3f [2] 84 25 [2] 9a 38 [2] 98 39 [2] 83 3f [2] 9f 38 [2] 83 17 }

  condition:
    any of them
}