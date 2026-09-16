rule TTP_XOR_QUAD_CurrentVersionRun_772b {
  strings:
    $key_772b = { 24 44 [2] 00 4a [2] 2b 66 [2] 05 44 [2] 11 5f [2] 1e 45 [2] 00 58 [2] 02 59 [2] 19 5f [2] 05 58 [2] 19 77 }

  condition:
    any of them
}