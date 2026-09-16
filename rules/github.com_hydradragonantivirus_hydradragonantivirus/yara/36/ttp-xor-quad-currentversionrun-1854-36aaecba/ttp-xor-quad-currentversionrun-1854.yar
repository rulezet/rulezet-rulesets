rule TTP_XOR_QUAD_CurrentVersionRun_1854 {
  strings:
    $key_1854 = { 4b 3b [2] 6f 35 [2] 44 19 [2] 6a 3b [2] 7e 20 [2] 71 3a [2] 6f 27 [2] 6d 26 [2] 76 20 [2] 6a 27 [2] 76 08 }

  condition:
    any of them
}