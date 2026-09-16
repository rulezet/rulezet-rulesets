rule TTP_XOR_QUAD_CurrentVersionRun_7735 {
  strings:
    $key_7735 = { 24 5a [2] 00 54 [2] 2b 78 [2] 05 5a [2] 11 41 [2] 1e 5b [2] 00 46 [2] 02 47 [2] 19 41 [2] 05 46 [2] 19 69 }

  condition:
    any of them
}