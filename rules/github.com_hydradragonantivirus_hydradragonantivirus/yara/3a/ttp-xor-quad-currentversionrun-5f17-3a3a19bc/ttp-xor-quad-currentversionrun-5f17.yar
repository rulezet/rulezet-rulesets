rule TTP_XOR_QUAD_CurrentVersionRun_5f17 {
  strings:
    $key_5f17 = { 0c 78 [2] 28 76 [2] 03 5a [2] 2d 78 [2] 39 63 [2] 36 79 [2] 28 64 [2] 2a 65 [2] 31 63 [2] 2d 64 [2] 31 4b }

  condition:
    any of them
}