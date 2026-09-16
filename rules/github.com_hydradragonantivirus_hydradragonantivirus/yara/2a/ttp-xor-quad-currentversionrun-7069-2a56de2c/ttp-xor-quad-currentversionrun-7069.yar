rule TTP_XOR_QUAD_CurrentVersionRun_7069 {
  strings:
    $key_7069 = { 23 06 [2] 07 08 [2] 2c 24 [2] 02 06 [2] 16 1d [2] 19 07 [2] 07 1a [2] 05 1b [2] 1e 1d [2] 02 1a [2] 1e 35 }

  condition:
    any of them
}