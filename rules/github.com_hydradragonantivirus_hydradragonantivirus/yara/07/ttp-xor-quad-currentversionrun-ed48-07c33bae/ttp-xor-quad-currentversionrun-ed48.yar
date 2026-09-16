rule TTP_XOR_QUAD_CurrentVersionRun_ed48 {
  strings:
    $key_ed48 = { be 27 [2] 9a 29 [2] b1 05 [2] 9f 27 [2] 8b 3c [2] 84 26 [2] 9a 3b [2] 98 3a [2] 83 3c [2] 9f 3b [2] 83 14 }

  condition:
    any of them
}