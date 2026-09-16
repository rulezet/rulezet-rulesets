rule TTP_XOR_QUAD_CurrentVersionRun_1837 {
  strings:
    $key_1837 = { 4b 58 [2] 6f 56 [2] 44 7a [2] 6a 58 [2] 7e 43 [2] 71 59 [2] 6f 44 [2] 6d 45 [2] 76 43 [2] 6a 44 [2] 76 6b }

  condition:
    any of them
}