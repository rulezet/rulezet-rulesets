rule TTP_XOR_QUAD_CurrentVersionRun_1f37 {
  strings:
    $key_1f37 = { 4c 58 [2] 68 56 [2] 43 7a [2] 6d 58 [2] 79 43 [2] 76 59 [2] 68 44 [2] 6a 45 [2] 71 43 [2] 6d 44 [2] 71 6b }

  condition:
    any of them
}