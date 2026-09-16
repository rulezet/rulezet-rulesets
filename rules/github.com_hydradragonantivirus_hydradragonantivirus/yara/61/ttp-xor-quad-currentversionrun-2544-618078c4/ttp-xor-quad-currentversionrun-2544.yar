rule TTP_XOR_QUAD_CurrentVersionRun_2544 {
  strings:
    $key_2544 = { 76 2b [2] 52 25 [2] 79 09 [2] 57 2b [2] 43 30 [2] 4c 2a [2] 52 37 [2] 50 36 [2] 4b 30 [2] 57 37 [2] 4b 18 }

  condition:
    any of them
}