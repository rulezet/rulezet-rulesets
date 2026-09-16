rule TTP_XOR_QUAD_CurrentVersionRun_0337 {
  strings:
    $key_0337 = { 50 58 [2] 74 56 [2] 5f 7a [2] 71 58 [2] 65 43 [2] 6a 59 [2] 74 44 [2] 76 45 [2] 6d 43 [2] 71 44 [2] 6d 6b }

  condition:
    any of them
}