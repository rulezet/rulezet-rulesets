rule TTP_XOR_QUAD_CurrentVersionRun_6656 {
  strings:
    $key_6656 = { 35 39 [2] 11 37 [2] 3a 1b [2] 14 39 [2] 00 22 [2] 0f 38 [2] 11 25 [2] 13 24 [2] 08 22 [2] 14 25 [2] 08 0a }

  condition:
    any of them
}