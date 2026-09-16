rule TTP_XOR_QUAD_CurrentVersionRun_2d37 {
  strings:
    $key_2d37 = { 7e 58 [2] 5a 56 [2] 71 7a [2] 5f 58 [2] 4b 43 [2] 44 59 [2] 5a 44 [2] 58 45 [2] 43 43 [2] 5f 44 [2] 43 6b }

  condition:
    any of them
}