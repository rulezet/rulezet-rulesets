rule TTP_XOR_QUAD_CurrentVersionRun_1e37 {
  strings:
    $key_1e37 = { 4d 58 [2] 69 56 [2] 42 7a [2] 6c 58 [2] 78 43 [2] 77 59 [2] 69 44 [2] 6b 45 [2] 70 43 [2] 6c 44 [2] 70 6b }

  condition:
    any of them
}