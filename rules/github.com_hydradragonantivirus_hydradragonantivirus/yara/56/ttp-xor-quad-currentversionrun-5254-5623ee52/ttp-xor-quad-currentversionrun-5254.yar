rule TTP_XOR_QUAD_CurrentVersionRun_5254 {
  strings:
    $key_5254 = { 01 3b [2] 25 35 [2] 0e 19 [2] 20 3b [2] 34 20 [2] 3b 3a [2] 25 27 [2] 27 26 [2] 3c 20 [2] 20 27 [2] 3c 08 }

  condition:
    any of them
}