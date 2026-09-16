rule TTP_XOR_QUAD_CurrentVersionRun_52e7 {
  strings:
    $key_52e7 = { 01 88 [2] 25 86 [2] 0e aa [2] 20 88 [2] 34 93 [2] 3b 89 [2] 25 94 [2] 27 95 [2] 3c 93 [2] 20 94 [2] 3c bb }

  condition:
    any of them
}