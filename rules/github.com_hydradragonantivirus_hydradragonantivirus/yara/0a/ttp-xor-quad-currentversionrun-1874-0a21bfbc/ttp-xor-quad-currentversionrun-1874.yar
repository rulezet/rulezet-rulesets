rule TTP_XOR_QUAD_CurrentVersionRun_1874 {
  strings:
    $key_1874 = { 4b 1b [2] 6f 15 [2] 44 39 [2] 6a 1b [2] 7e 00 [2] 71 1a [2] 6f 07 [2] 6d 06 [2] 76 00 [2] 6a 07 [2] 76 28 }

  condition:
    any of them
}