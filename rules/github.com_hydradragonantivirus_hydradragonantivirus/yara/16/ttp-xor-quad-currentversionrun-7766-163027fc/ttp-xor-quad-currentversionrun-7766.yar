rule TTP_XOR_QUAD_CurrentVersionRun_7766 {
  strings:
    $key_7766 = { 24 09 [2] 00 07 [2] 2b 2b [2] 05 09 [2] 11 12 [2] 1e 08 [2] 00 15 [2] 02 14 [2] 19 12 [2] 05 15 [2] 19 3a }

  condition:
    any of them
}