rule TTP_XOR_QUAD_CurrentVersionRun_7c36 {
  strings:
    $key_7c36 = { 2f 59 [2] 0b 57 [2] 20 7b [2] 0e 59 [2] 1a 42 [2] 15 58 [2] 0b 45 [2] 09 44 [2] 12 42 [2] 0e 45 [2] 12 6a }

  condition:
    any of them
}