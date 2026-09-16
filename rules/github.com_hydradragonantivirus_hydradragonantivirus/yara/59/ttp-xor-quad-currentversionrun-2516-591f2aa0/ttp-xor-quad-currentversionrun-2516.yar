rule TTP_XOR_QUAD_CurrentVersionRun_2516 {
  strings:
    $key_2516 = { 76 79 [2] 52 77 [2] 79 5b [2] 57 79 [2] 43 62 [2] 4c 78 [2] 52 65 [2] 50 64 [2] 4b 62 [2] 57 65 [2] 4b 4a }

  condition:
    any of them
}