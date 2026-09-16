rule TTP_XOR_QUAD_CurrentVersionRun_4055 {
  strings:
    $key_4055 = { 13 3a [2] 37 34 [2] 1c 18 [2] 32 3a [2] 26 21 [2] 29 3b [2] 37 26 [2] 35 27 [2] 2e 21 [2] 32 26 [2] 2e 09 }

  condition:
    any of them
}