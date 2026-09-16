rule TTP_XOR_QUAD_CurrentVersionRun_2d57 {
  strings:
    $key_2d57 = { 7e 38 [2] 5a 36 [2] 71 1a [2] 5f 38 [2] 4b 23 [2] 44 39 [2] 5a 24 [2] 58 25 [2] 43 23 [2] 5f 24 [2] 43 0b }

  condition:
    any of them
}