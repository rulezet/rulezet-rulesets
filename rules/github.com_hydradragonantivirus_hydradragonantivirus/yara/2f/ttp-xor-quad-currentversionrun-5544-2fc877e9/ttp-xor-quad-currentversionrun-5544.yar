rule TTP_XOR_QUAD_CurrentVersionRun_5544 {
  strings:
    $key_5544 = { 06 2b [2] 22 25 [2] 09 09 [2] 27 2b [2] 33 30 [2] 3c 2a [2] 22 37 [2] 20 36 [2] 3b 30 [2] 27 37 [2] 3b 18 }

  condition:
    any of them
}