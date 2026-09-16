rule TTP_XOR_QUAD_CurrentVersionRun_776b {
  strings:
    $key_776b = { 24 04 [2] 00 0a [2] 2b 26 [2] 05 04 [2] 11 1f [2] 1e 05 [2] 00 18 [2] 02 19 [2] 19 1f [2] 05 18 [2] 19 37 }

  condition:
    any of them
}