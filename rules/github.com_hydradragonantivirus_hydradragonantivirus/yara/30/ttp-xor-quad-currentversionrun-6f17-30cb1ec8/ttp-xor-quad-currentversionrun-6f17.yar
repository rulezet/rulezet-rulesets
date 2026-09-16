rule TTP_XOR_QUAD_CurrentVersionRun_6f17 {
  strings:
    $key_6f17 = { 3c 78 [2] 18 76 [2] 33 5a [2] 1d 78 [2] 09 63 [2] 06 79 [2] 18 64 [2] 1a 65 [2] 01 63 [2] 1d 64 [2] 01 4b }

  condition:
    any of them
}