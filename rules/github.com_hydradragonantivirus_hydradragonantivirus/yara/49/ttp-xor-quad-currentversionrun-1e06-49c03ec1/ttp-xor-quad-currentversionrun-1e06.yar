rule TTP_XOR_QUAD_CurrentVersionRun_1e06 {
  strings:
    $key_1e06 = { 4d 69 [2] 69 67 [2] 42 4b [2] 6c 69 [2] 78 72 [2] 77 68 [2] 69 75 [2] 6b 74 [2] 70 72 [2] 6c 75 [2] 70 5a }

  condition:
    any of them
}