rule TTP_XOR_QUAD_CurrentVersionRun_634b {
  strings:
    $key_634b = { 30 24 [2] 14 2a [2] 3f 06 [2] 11 24 [2] 05 3f [2] 0a 25 [2] 14 38 [2] 16 39 [2] 0d 3f [2] 11 38 [2] 0d 17 }

  condition:
    any of them
}