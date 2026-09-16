rule TTP_XOR_QUAD_CurrentVersionRun_1555 {
  strings:
    $key_1555 = { 46 3a [2] 62 34 [2] 49 18 [2] 67 3a [2] 73 21 [2] 7c 3b [2] 62 26 [2] 60 27 [2] 7b 21 [2] 67 26 [2] 7b 09 }

  condition:
    any of them
}