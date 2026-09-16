rule TTP_XOR_QUAD_CurrentVersionRun_1a37 {
  strings:
    $key_1a37 = { 49 58 [2] 6d 56 [2] 46 7a [2] 68 58 [2] 7c 43 [2] 73 59 [2] 6d 44 [2] 6f 45 [2] 74 43 [2] 68 44 [2] 74 6b }

  condition:
    any of them
}