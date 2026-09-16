rule TTP_XOR_QUAD_CurrentVersionRun_ed75 {
  strings:
    $key_ed75 = { be 1a [2] 9a 14 [2] b1 38 [2] 9f 1a [2] 8b 01 [2] 84 1b [2] 9a 06 [2] 98 07 [2] 83 01 [2] 9f 06 [2] 83 29 }

  condition:
    any of them
}