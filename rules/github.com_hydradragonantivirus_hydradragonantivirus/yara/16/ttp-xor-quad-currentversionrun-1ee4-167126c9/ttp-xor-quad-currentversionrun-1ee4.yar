rule TTP_XOR_QUAD_CurrentVersionRun_1ee4 {
  strings:
    $key_1ee4 = { 4d 8b [2] 69 85 [2] 42 a9 [2] 6c 8b [2] 78 90 [2] 77 8a [2] 69 97 [2] 6b 96 [2] 70 90 [2] 6c 97 [2] 70 b8 }

  condition:
    any of them
}