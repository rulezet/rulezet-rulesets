rule TTP_XOR_QUAD_CurrentVersionRun_644b {
  strings:
    $key_644b = { 37 24 [2] 13 2a [2] 38 06 [2] 16 24 [2] 02 3f [2] 0d 25 [2] 13 38 [2] 11 39 [2] 0a 3f [2] 16 38 [2] 0a 17 }

  condition:
    any of them
}