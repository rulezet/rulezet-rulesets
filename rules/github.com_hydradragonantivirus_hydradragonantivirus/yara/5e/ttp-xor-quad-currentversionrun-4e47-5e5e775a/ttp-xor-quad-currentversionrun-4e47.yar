rule TTP_XOR_QUAD_CurrentVersionRun_4e47 {
  strings:
    $key_4e47 = { 1d 28 [2] 39 26 [2] 12 0a [2] 3c 28 [2] 28 33 [2] 27 29 [2] 39 34 [2] 3b 35 [2] 20 33 [2] 3c 34 [2] 20 1b }

  condition:
    any of them
}