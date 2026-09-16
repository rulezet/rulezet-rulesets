rule TTP_XOR_QUAD_CurrentVersionRun_1e16 {
  strings:
    $key_1e16 = { 4d 79 [2] 69 77 [2] 42 5b [2] 6c 79 [2] 78 62 [2] 77 78 [2] 69 65 [2] 6b 64 [2] 70 62 [2] 6c 65 [2] 70 4a }

  condition:
    any of them
}