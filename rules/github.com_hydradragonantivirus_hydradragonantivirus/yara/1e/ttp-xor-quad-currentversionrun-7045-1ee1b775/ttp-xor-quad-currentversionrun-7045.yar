rule TTP_XOR_QUAD_CurrentVersionRun_7045 {
  strings:
    $key_7045 = { 23 2a [2] 07 24 [2] 2c 08 [2] 02 2a [2] 16 31 [2] 19 2b [2] 07 36 [2] 05 37 [2] 1e 31 [2] 02 36 [2] 1e 19 }

  condition:
    any of them
}