rule TTP_XOR_QUAD_CurrentVersionRun_6a47 {
  strings:
    $key_6a47 = { 39 28 [2] 1d 26 [2] 36 0a [2] 18 28 [2] 0c 33 [2] 03 29 [2] 1d 34 [2] 1f 35 [2] 04 33 [2] 18 34 [2] 04 1b }

  condition:
    any of them
}