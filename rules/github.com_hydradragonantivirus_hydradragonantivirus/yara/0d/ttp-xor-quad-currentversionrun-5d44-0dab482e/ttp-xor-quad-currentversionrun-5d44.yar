rule TTP_XOR_QUAD_CurrentVersionRun_5d44 {
  strings:
    $key_5d44 = { 0e 2b [2] 2a 25 [2] 01 09 [2] 2f 2b [2] 3b 30 [2] 34 2a [2] 2a 37 [2] 28 36 [2] 33 30 [2] 2f 37 [2] 33 18 }

  condition:
    any of them
}