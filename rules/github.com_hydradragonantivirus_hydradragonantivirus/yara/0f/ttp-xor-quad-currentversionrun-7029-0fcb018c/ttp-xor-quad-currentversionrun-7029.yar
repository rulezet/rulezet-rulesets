rule TTP_XOR_QUAD_CurrentVersionRun_7029 {
  strings:
    $key_7029 = { 23 46 [2] 07 48 [2] 2c 64 [2] 02 46 [2] 16 5d [2] 19 47 [2] 07 5a [2] 05 5b [2] 1e 5d [2] 02 5a [2] 1e 75 }

  condition:
    any of them
}