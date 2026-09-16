rule TTP_XOR_QUAD_CurrentVersionRun_7724 {
  strings:
    $key_7724 = { 24 4b [2] 00 45 [2] 2b 69 [2] 05 4b [2] 11 50 [2] 1e 4a [2] 00 57 [2] 02 56 [2] 19 50 [2] 05 57 [2] 19 78 }

  condition:
    any of them
}