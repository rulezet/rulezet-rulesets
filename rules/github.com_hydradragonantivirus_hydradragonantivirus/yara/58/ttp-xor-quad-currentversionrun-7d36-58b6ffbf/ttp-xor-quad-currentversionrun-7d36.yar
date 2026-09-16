rule TTP_XOR_QUAD_CurrentVersionRun_7d36 {
  strings:
    $key_7d36 = { 2e 59 [2] 0a 57 [2] 21 7b [2] 0f 59 [2] 1b 42 [2] 14 58 [2] 0a 45 [2] 08 44 [2] 13 42 [2] 0f 45 [2] 13 6a }

  condition:
    any of them
}