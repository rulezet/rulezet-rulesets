rule TTP_XOR_QUAD_CurrentVersionRun_1855 {
  strings:
    $key_1855 = { 4b 3a [2] 6f 34 [2] 44 18 [2] 6a 3a [2] 7e 21 [2] 71 3b [2] 6f 26 [2] 6d 27 [2] 76 21 [2] 6a 26 [2] 76 09 }

  condition:
    any of them
}