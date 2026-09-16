rule TTP_XOR_QUAD_CurrentVersionRun_7759 {
  strings:
    $key_7759 = { 24 36 [2] 00 38 [2] 2b 14 [2] 05 36 [2] 11 2d [2] 1e 37 [2] 00 2a [2] 02 2b [2] 19 2d [2] 05 2a [2] 19 05 }

  condition:
    any of them
}