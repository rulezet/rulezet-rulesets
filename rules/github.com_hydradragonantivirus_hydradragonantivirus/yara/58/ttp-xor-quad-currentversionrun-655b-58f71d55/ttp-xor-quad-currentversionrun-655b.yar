rule TTP_XOR_QUAD_CurrentVersionRun_655b {
  strings:
    $key_655b = { 36 34 [2] 12 3a [2] 39 16 [2] 17 34 [2] 03 2f [2] 0c 35 [2] 12 28 [2] 10 29 [2] 0b 2f [2] 17 28 [2] 0b 07 }

  condition:
    any of them
}