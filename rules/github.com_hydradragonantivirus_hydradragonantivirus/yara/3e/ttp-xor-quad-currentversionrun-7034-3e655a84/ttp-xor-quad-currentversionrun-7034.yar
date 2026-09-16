rule TTP_XOR_QUAD_CurrentVersionRun_7034 {
  strings:
    $key_7034 = { 23 5b [2] 07 55 [2] 2c 79 [2] 02 5b [2] 16 40 [2] 19 5a [2] 07 47 [2] 05 46 [2] 1e 40 [2] 02 47 [2] 1e 68 }

  condition:
    any of them
}