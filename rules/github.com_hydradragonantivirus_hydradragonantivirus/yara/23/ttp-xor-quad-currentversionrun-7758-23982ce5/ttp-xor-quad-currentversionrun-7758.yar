rule TTP_XOR_QUAD_CurrentVersionRun_7758 {
  strings:
    $key_7758 = { 24 37 [2] 00 39 [2] 2b 15 [2] 05 37 [2] 11 2c [2] 1e 36 [2] 00 2b [2] 02 2a [2] 19 2c [2] 05 2b [2] 19 04 }

  condition:
    any of them
}