rule TTP_XOR_QUAD_CurrentVersionRun_3e37 {
  strings:
    $key_3e37 = { 6d 58 [2] 49 56 [2] 62 7a [2] 4c 58 [2] 58 43 [2] 57 59 [2] 49 44 [2] 4b 45 [2] 50 43 [2] 4c 44 [2] 50 6b }

  condition:
    any of them
}