rule TTP_XOR_QUAD_CurrentVersionRun_3454 {
  strings:
    $key_3454 = { 67 3b [2] 43 35 [2] 68 19 [2] 46 3b [2] 52 20 [2] 5d 3a [2] 43 27 [2] 41 26 [2] 5a 20 [2] 46 27 [2] 5a 08 }

  condition:
    any of them
}