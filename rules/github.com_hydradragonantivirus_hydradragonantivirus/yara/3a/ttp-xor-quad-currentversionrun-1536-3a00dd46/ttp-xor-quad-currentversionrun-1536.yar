rule TTP_XOR_QUAD_CurrentVersionRun_1536 {
  strings:
    $key_1536 = { 46 59 [2] 62 57 [2] 49 7b [2] 67 59 [2] 73 42 [2] 7c 58 [2] 62 45 [2] 60 44 [2] 7b 42 [2] 67 45 [2] 7b 6a }

  condition:
    any of them
}