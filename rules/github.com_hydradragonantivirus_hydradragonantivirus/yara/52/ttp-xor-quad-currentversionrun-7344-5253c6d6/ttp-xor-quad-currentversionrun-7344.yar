rule TTP_XOR_QUAD_CurrentVersionRun_7344 {
  strings:
    $key_7344 = { 20 2b [2] 04 25 [2] 2f 09 [2] 01 2b [2] 15 30 [2] 1a 2a [2] 04 37 [2] 06 36 [2] 1d 30 [2] 01 37 [2] 1d 18 }

  condition:
    any of them
}