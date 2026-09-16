rule TTP_XOR_QUAD_CurrentVersionRun_0137 {
  strings:
    $key_0137 = { 52 58 [2] 76 56 [2] 5d 7a [2] 73 58 [2] 67 43 [2] 68 59 [2] 76 44 [2] 74 45 [2] 6f 43 [2] 73 44 [2] 6f 6b }

  condition:
    any of them
}