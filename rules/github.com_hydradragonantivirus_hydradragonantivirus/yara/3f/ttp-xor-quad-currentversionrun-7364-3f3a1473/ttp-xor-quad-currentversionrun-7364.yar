rule TTP_XOR_QUAD_CurrentVersionRun_7364 {
  strings:
    $key_7364 = { 20 0b [2] 04 05 [2] 2f 29 [2] 01 0b [2] 15 10 [2] 1a 0a [2] 04 17 [2] 06 16 [2] 1d 10 [2] 01 17 [2] 1d 38 }

  condition:
    any of them
}