rule TTP_XOR_QUAD_CurrentVersionRun_2d45 {
  strings:
    $key_2d45 = { 7e 2a [2] 5a 24 [2] 71 08 [2] 5f 2a [2] 4b 31 [2] 44 2b [2] 5a 36 [2] 58 37 [2] 43 31 [2] 5f 36 [2] 43 19 }

  condition:
    any of them
}