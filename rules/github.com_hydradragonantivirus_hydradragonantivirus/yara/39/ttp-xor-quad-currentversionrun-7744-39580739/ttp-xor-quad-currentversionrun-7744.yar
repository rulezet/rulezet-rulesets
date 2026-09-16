rule TTP_XOR_QUAD_CurrentVersionRun_7744 {
  strings:
    $key_7744 = { 24 2b [2] 00 25 [2] 2b 09 [2] 05 2b [2] 11 30 [2] 1e 2a [2] 00 37 [2] 02 36 [2] 19 30 [2] 05 37 [2] 19 18 }

  condition:
    any of them
}