rule TTP_XOR_QUAD_CurrentVersionRun_1637 {
  strings:
    $key_1637 = { 45 58 [2] 61 56 [2] 4a 7a [2] 64 58 [2] 70 43 [2] 7f 59 [2] 61 44 [2] 63 45 [2] 78 43 [2] 64 44 [2] 78 6b }

  condition:
    any of them
}