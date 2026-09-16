rule TTP_XOR_QUAD_CurrentVersionRun_4327 {
  strings:
    $key_4327 = { 10 48 [2] 34 46 [2] 1f 6a [2] 31 48 [2] 25 53 [2] 2a 49 [2] 34 54 [2] 36 55 [2] 2d 53 [2] 31 54 [2] 2d 7b }

  condition:
    any of them
}