rule TTP_XOR_QUAD_CurrentVersionRun_7937 {
  strings:
    $key_7937 = { 2a 58 [2] 0e 56 [2] 25 7a [2] 0b 58 [2] 1f 43 [2] 10 59 [2] 0e 44 [2] 0c 45 [2] 17 43 [2] 0b 44 [2] 17 6b }

  condition:
    any of them
}