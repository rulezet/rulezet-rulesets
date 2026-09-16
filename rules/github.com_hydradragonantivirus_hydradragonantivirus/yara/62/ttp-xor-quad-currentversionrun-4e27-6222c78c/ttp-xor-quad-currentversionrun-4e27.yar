rule TTP_XOR_QUAD_CurrentVersionRun_4e27 {
  strings:
    $key_4e27 = { 1d 48 [2] 39 46 [2] 12 6a [2] 3c 48 [2] 28 53 [2] 27 49 [2] 39 54 [2] 3b 55 [2] 20 53 [2] 3c 54 [2] 20 7b }

  condition:
    any of them
}