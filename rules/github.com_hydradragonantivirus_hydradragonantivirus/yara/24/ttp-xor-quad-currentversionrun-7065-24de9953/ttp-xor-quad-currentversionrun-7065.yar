rule TTP_XOR_QUAD_CurrentVersionRun_7065 {
  strings:
    $key_7065 = { 23 0a [2] 07 04 [2] 2c 28 [2] 02 0a [2] 16 11 [2] 19 0b [2] 07 16 [2] 05 17 [2] 1e 11 [2] 02 16 [2] 1e 39 }

  condition:
    any of them
}