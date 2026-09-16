rule TTP_XOR_QUAD_CurrentVersionRun_1436 {
  strings:
    $key_1436 = { 47 59 [2] 63 57 [2] 48 7b [2] 66 59 [2] 72 42 [2] 7d 58 [2] 63 45 [2] 61 44 [2] 7a 42 [2] 66 45 [2] 7a 6a }

  condition:
    any of them
}