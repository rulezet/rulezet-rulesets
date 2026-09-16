rule TTP_XOR_QUAD_CurrentVersionRun_7748 {
  strings:
    $key_7748 = { 24 27 [2] 00 29 [2] 2b 05 [2] 05 27 [2] 11 3c [2] 1e 26 [2] 00 3b [2] 02 3a [2] 19 3c [2] 05 3b [2] 19 14 }

  condition:
    any of them
}