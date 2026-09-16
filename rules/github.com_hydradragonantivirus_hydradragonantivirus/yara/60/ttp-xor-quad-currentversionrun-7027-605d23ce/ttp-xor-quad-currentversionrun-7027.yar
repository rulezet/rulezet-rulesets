rule TTP_XOR_QUAD_CurrentVersionRun_7027 {
  strings:
    $key_7027 = { 23 48 [2] 07 46 [2] 2c 6a [2] 02 48 [2] 16 53 [2] 19 49 [2] 07 54 [2] 05 55 [2] 1e 53 [2] 02 54 [2] 1e 7b }

  condition:
    any of them
}