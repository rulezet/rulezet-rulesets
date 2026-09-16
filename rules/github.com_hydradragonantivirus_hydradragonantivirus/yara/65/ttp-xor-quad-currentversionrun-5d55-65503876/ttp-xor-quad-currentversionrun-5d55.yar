rule TTP_XOR_QUAD_CurrentVersionRun_5d55 {
  strings:
    $key_5d55 = { 0e 3a [2] 2a 34 [2] 01 18 [2] 2f 3a [2] 3b 21 [2] 34 3b [2] 2a 26 [2] 28 27 [2] 33 21 [2] 2f 26 [2] 33 09 }

  condition:
    any of them
}