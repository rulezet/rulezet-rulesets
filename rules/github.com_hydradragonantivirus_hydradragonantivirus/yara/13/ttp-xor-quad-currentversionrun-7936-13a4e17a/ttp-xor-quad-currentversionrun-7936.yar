rule TTP_XOR_QUAD_CurrentVersionRun_7936 {
  strings:
    $key_7936 = { 2a 59 [2] 0e 57 [2] 25 7b [2] 0b 59 [2] 1f 42 [2] 10 58 [2] 0e 45 [2] 0c 44 [2] 17 42 [2] 0b 45 [2] 17 6a }

  condition:
    any of them
}