rule TTP_XOR_QUAD_CurrentVersionRun_6f6b {
  strings:
    $key_6f6b = { 3c 04 [2] 18 0a [2] 33 26 [2] 1d 04 [2] 09 1f [2] 06 05 [2] 18 18 [2] 1a 19 [2] 01 1f [2] 1d 18 [2] 01 37 }

  condition:
    any of them
}