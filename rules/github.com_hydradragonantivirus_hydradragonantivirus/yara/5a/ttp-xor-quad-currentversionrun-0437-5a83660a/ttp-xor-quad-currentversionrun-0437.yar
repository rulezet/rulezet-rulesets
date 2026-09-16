rule TTP_XOR_QUAD_CurrentVersionRun_0437 {
  strings:
    $key_0437 = { 57 58 [2] 73 56 [2] 58 7a [2] 76 58 [2] 62 43 [2] 6d 59 [2] 73 44 [2] 71 45 [2] 6a 43 [2] 76 44 [2] 6a 6b }

  condition:
    any of them
}