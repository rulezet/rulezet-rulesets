rule TTP_XOR_QUAD_CurrentVersionRun_2e36 {
  strings:
    $key_2e36 = { 7d 59 [2] 59 57 [2] 72 7b [2] 5c 59 [2] 48 42 [2] 47 58 [2] 59 45 [2] 5b 44 [2] 40 42 [2] 5c 45 [2] 40 6a }

  condition:
    any of them
}