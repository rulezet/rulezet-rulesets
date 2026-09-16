rule TTP_XOR_QUAD_CurrentVersionRun_4e17 {
  strings:
    $key_4e17 = { 1d 78 [2] 39 76 [2] 12 5a [2] 3c 78 [2] 28 63 [2] 27 79 [2] 39 64 [2] 3b 65 [2] 20 63 [2] 3c 64 [2] 20 4b }

  condition:
    any of them
}