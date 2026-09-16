rule TTP_XOR_QUAD_CurrentVersionRun_7704 {
  strings:
    $key_7704 = { 24 6b [2] 00 65 [2] 2b 49 [2] 05 6b [2] 11 70 [2] 1e 6a [2] 00 77 [2] 02 76 [2] 19 70 [2] 05 77 [2] 19 58 }

  condition:
    any of them
}