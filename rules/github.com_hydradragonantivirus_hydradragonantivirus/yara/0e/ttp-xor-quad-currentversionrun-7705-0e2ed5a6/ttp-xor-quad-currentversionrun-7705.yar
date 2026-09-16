rule TTP_XOR_QUAD_CurrentVersionRun_7705 {
  strings:
    $key_7705 = { 24 6a [2] 00 64 [2] 2b 48 [2] 05 6a [2] 11 71 [2] 1e 6b [2] 00 76 [2] 02 77 [2] 19 71 [2] 05 76 [2] 19 59 }

  condition:
    any of them
}