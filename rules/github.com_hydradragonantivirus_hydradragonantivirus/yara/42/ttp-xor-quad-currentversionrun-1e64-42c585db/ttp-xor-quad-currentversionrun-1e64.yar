rule TTP_XOR_QUAD_CurrentVersionRun_1e64 {
  strings:
    $key_1e64 = { 4d 0b [2] 69 05 [2] 42 29 [2] 6c 0b [2] 78 10 [2] 77 0a [2] 69 17 [2] 6b 16 [2] 70 10 [2] 6c 17 [2] 70 38 }

  condition:
    any of them
}