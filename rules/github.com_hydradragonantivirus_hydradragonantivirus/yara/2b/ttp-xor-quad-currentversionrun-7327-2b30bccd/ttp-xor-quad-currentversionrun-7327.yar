rule TTP_XOR_QUAD_CurrentVersionRun_7327 {
  strings:
    $key_7327 = { 20 48 [2] 04 46 [2] 2f 6a [2] 01 48 [2] 15 53 [2] 1a 49 [2] 04 54 [2] 06 55 [2] 1d 53 [2] 01 54 [2] 1d 7b }

  condition:
    any of them
}