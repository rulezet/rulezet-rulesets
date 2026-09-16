rule TTP_XOR_QUAD_CurrentVersionRun_770b {
  strings:
    $key_770b = { 24 64 [2] 00 6a [2] 2b 46 [2] 05 64 [2] 11 7f [2] 1e 65 [2] 00 78 [2] 02 79 [2] 19 7f [2] 05 78 [2] 19 57 }

  condition:
    any of them
}