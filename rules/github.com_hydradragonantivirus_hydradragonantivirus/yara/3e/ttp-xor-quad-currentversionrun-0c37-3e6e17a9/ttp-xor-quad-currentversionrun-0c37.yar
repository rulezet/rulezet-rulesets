rule TTP_XOR_QUAD_CurrentVersionRun_0c37 {
  strings:
    $key_0c37 = { 5f 58 [2] 7b 56 [2] 50 7a [2] 7e 58 [2] 6a 43 [2] 65 59 [2] 7b 44 [2] 79 45 [2] 62 43 [2] 7e 44 [2] 62 6b }

  condition:
    any of them
}