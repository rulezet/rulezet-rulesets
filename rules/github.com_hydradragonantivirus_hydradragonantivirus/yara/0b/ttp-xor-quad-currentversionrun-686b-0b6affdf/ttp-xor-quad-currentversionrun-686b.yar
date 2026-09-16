rule TTP_XOR_QUAD_CurrentVersionRun_686b {
  strings:
    $key_686b = { 3b 04 [2] 1f 0a [2] 34 26 [2] 1a 04 [2] 0e 1f [2] 01 05 [2] 1f 18 [2] 1d 19 [2] 06 1f [2] 1a 18 [2] 06 37 }

  condition:
    any of them
}