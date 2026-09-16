rule TTP_XOR_QUAD_CurrentVersionRun_7739 {
  strings:
    $key_7739 = { 24 56 [2] 00 58 [2] 2b 74 [2] 05 56 [2] 11 4d [2] 1e 57 [2] 00 4a [2] 02 4b [2] 19 4d [2] 05 4a [2] 19 65 }

  condition:
    any of them
}