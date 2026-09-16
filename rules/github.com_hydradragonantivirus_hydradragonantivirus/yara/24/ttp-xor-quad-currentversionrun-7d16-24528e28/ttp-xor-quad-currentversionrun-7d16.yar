rule TTP_XOR_QUAD_CurrentVersionRun_7d16 {
  strings:
    $key_7d16 = { 2e 79 [2] 0a 77 [2] 21 5b [2] 0f 79 [2] 1b 62 [2] 14 78 [2] 0a 65 [2] 08 64 [2] 13 62 [2] 0f 65 [2] 13 4a }

  condition:
    any of them
}