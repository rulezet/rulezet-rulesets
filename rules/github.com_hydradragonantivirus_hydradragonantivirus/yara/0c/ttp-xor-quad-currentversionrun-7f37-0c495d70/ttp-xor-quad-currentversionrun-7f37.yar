rule TTP_XOR_QUAD_CurrentVersionRun_7f37 {
  strings:
    $key_7f37 = { 2c 58 [2] 08 56 [2] 23 7a [2] 0d 58 [2] 19 43 [2] 16 59 [2] 08 44 [2] 0a 45 [2] 11 43 [2] 0d 44 [2] 11 6b }

  condition:
    any of them
}