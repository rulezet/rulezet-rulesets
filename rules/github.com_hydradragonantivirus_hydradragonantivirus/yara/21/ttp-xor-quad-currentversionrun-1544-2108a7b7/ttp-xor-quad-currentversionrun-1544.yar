rule TTP_XOR_QUAD_CurrentVersionRun_1544 {
  strings:
    $key_1544 = { 46 2b [2] 62 25 [2] 49 09 [2] 67 2b [2] 73 30 [2] 7c 2a [2] 62 37 [2] 60 36 [2] 7b 30 [2] 67 37 [2] 7b 18 }

  condition:
    any of them
}