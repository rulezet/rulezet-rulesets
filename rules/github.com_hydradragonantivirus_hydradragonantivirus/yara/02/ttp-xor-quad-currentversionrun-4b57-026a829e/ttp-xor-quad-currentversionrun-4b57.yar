rule TTP_XOR_QUAD_CurrentVersionRun_4b57 {
  strings:
    $key_4b57 = { 18 38 [2] 3c 36 [2] 17 1a [2] 39 38 [2] 2d 23 [2] 22 39 [2] 3c 24 [2] 3e 25 [2] 25 23 [2] 39 24 [2] 25 0b }

  condition:
    any of them
}