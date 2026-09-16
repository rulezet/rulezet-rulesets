rule TTP_XOR_QUAD_CurrentVersionRun_2d44 {
  strings:
    $key_2d44 = { 7e 2b [2] 5a 25 [2] 71 09 [2] 5f 2b [2] 4b 30 [2] 44 2a [2] 5a 37 [2] 58 36 [2] 43 30 [2] 5f 37 [2] 43 18 }

  condition:
    any of them
}