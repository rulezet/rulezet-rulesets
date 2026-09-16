rule TTP_XOR_QUAD_CurrentVersionRun_774b {
  strings:
    $key_774b = { 24 24 [2] 00 2a [2] 2b 06 [2] 05 24 [2] 11 3f [2] 1e 25 [2] 00 38 [2] 02 39 [2] 19 3f [2] 05 38 [2] 19 17 }

  condition:
    any of them
}