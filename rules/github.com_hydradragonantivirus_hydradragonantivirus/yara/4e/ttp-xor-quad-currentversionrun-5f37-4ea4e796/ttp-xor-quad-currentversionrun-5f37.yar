rule TTP_XOR_QUAD_CurrentVersionRun_5f37 {
  strings:
    $key_5f37 = { 0c 58 [2] 28 56 [2] 03 7a [2] 2d 58 [2] 39 43 [2] 36 59 [2] 28 44 [2] 2a 45 [2] 31 43 [2] 2d 44 [2] 31 6b }

  condition:
    any of them
}