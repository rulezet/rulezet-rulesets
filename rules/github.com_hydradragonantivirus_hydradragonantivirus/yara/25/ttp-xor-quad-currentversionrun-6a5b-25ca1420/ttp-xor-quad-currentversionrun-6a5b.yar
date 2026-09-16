rule TTP_XOR_QUAD_CurrentVersionRun_6a5b {
  strings:
    $key_6a5b = { 39 34 [2] 1d 3a [2] 36 16 [2] 18 34 [2] 0c 2f [2] 03 35 [2] 1d 28 [2] 1f 29 [2] 04 2f [2] 18 28 [2] 04 07 }

  condition:
    any of them
}