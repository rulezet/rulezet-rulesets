rule TTP_XOR_QUAD_CurrentVersionRun_6327 {
  strings:
    $key_6327 = { 30 48 [2] 14 46 [2] 3f 6a [2] 11 48 [2] 05 53 [2] 0a 49 [2] 14 54 [2] 16 55 [2] 0d 53 [2] 11 54 [2] 0d 7b }

  condition:
    any of them
}