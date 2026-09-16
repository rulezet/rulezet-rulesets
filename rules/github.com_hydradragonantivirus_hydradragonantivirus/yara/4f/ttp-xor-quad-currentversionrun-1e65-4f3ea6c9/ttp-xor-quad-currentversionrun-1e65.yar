rule TTP_XOR_QUAD_CurrentVersionRun_1e65 {
  strings:
    $key_1e65 = { 4d 0a [2] 69 04 [2] 42 28 [2] 6c 0a [2] 78 11 [2] 77 0b [2] 69 16 [2] 6b 17 [2] 70 11 [2] 6c 16 [2] 70 39 }

  condition:
    any of them
}