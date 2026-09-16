rule TTP_XOR_QUAD_CurrentVersionRun_6f4b {
  strings:
    $key_6f4b = { 3c 24 [2] 18 2a [2] 33 06 [2] 1d 24 [2] 09 3f [2] 06 25 [2] 18 38 [2] 1a 39 [2] 01 3f [2] 1d 38 [2] 01 17 }

  condition:
    any of them
}