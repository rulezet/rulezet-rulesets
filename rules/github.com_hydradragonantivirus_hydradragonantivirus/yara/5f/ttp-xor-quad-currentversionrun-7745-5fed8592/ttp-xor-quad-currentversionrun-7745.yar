rule TTP_XOR_QUAD_CurrentVersionRun_7745 {
  strings:
    $key_7745 = { 24 2a [2] 00 24 [2] 2b 08 [2] 05 2a [2] 11 31 [2] 1e 2b [2] 00 36 [2] 02 37 [2] 19 31 [2] 05 36 [2] 19 19 }

  condition:
    any of them
}