rule TTP_XOR_QUAD_CurrentVersionRun_2137 {
  strings:
    $key_2137 = { 72 58 [2] 56 56 [2] 7d 7a [2] 53 58 [2] 47 43 [2] 48 59 [2] 56 44 [2] 54 45 [2] 4f 43 [2] 53 44 [2] 4f 6b }

  condition:
    any of them
}