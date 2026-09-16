rule TTP_XOR_QUAD_CurrentVersionRun_1e36 {
  strings:
    $key_1e36 = { 4d 59 [2] 69 57 [2] 42 7b [2] 6c 59 [2] 78 42 [2] 77 58 [2] 69 45 [2] 6b 44 [2] 70 42 [2] 6c 45 [2] 70 6a }

  condition:
    any of them
}