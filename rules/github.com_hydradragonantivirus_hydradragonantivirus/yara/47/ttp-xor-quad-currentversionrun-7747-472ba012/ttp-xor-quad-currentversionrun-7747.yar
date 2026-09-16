rule TTP_XOR_QUAD_CurrentVersionRun_7747 {
  strings:
    $key_7747 = { 24 28 [2] 00 26 [2] 2b 0a [2] 05 28 [2] 11 33 [2] 1e 29 [2] 00 34 [2] 02 35 [2] 19 33 [2] 05 34 [2] 19 1b }

  condition:
    any of them
}