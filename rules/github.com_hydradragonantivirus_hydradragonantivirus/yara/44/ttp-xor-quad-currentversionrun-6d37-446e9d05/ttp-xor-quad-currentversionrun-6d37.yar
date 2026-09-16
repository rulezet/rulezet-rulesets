rule TTP_XOR_QUAD_CurrentVersionRun_6d37 {
  strings:
    $key_6d37 = { 3e 58 [2] 1a 56 [2] 31 7a [2] 1f 58 [2] 0b 43 [2] 04 59 [2] 1a 44 [2] 18 45 [2] 03 43 [2] 1f 44 [2] 03 6b }

  condition:
    any of them
}