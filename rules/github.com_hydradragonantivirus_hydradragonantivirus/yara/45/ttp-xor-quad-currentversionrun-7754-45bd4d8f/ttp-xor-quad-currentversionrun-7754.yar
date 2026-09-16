rule TTP_XOR_QUAD_CurrentVersionRun_7754 {
  strings:
    $key_7754 = { 24 3b [2] 00 35 [2] 2b 19 [2] 05 3b [2] 11 20 [2] 1e 3a [2] 00 27 [2] 02 26 [2] 19 20 [2] 05 27 [2] 19 08 }

  condition:
    any of them
}