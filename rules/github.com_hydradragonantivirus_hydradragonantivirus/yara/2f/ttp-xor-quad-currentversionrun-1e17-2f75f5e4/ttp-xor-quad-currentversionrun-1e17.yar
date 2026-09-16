rule TTP_XOR_QUAD_CurrentVersionRun_1e17 {
  strings:
    $key_1e17 = { 4d 78 [2] 69 76 [2] 42 5a [2] 6c 78 [2] 78 63 [2] 77 79 [2] 69 64 [2] 6b 65 [2] 70 63 [2] 6c 64 [2] 70 4b }

  condition:
    any of them
}