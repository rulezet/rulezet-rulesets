rule TTP_XOR_QUAD_CurrentVersionRun_ed44 {
  strings:
    $key_ed44 = { be 2b [2] 9a 25 [2] b1 09 [2] 9f 2b [2] 8b 30 [2] 84 2a [2] 9a 37 [2] 98 36 [2] 83 30 [2] 9f 37 [2] 83 18 }

  condition:
    any of them
}