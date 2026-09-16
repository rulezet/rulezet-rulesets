rule TTP_XOR_QUAD_CurrentVersionRun_5f27 {
  strings:
    $key_5f27 = { 0c 48 [2] 28 46 [2] 03 6a [2] 2d 48 [2] 39 53 [2] 36 49 [2] 28 54 [2] 2a 55 [2] 31 53 [2] 2d 54 [2] 31 7b }

  condition:
    any of them
}