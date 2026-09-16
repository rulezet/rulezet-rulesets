rule TTP_XOR_QUAD_CurrentVersionRun_2744 {
  strings:
    $key_2744 = { 74 2b [2] 50 25 [2] 7b 09 [2] 55 2b [2] 41 30 [2] 4e 2a [2] 50 37 [2] 52 36 [2] 49 30 [2] 55 37 [2] 49 18 }

  condition:
    any of them
}