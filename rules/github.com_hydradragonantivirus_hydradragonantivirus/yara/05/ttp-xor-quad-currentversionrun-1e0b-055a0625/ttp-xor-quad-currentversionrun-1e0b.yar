rule TTP_XOR_QUAD_CurrentVersionRun_1e0b {
  strings:
    $key_1e0b = { 4d 64 [2] 69 6a [2] 42 46 [2] 6c 64 [2] 78 7f [2] 77 65 [2] 69 78 [2] 6b 79 [2] 70 7f [2] 6c 78 [2] 70 57 }

  condition:
    any of them
}