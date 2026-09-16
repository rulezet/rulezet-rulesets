rule TTP_XOR_QUAD_CurrentVersionRun_4c16 {
  strings:
    $key_4c16 = { 1f 79 [2] 3b 77 [2] 10 5b [2] 3e 79 [2] 2a 62 [2] 25 78 [2] 3b 65 [2] 39 64 [2] 22 62 [2] 3e 65 [2] 22 4a }

  condition:
    any of them
}